use anyhow::{Context, Result};
use ark_std::rand::RngCore;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, DirEntry};
use std::io::{Write, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{rand_core::OsRng as Argon2Rng, SaltString, PasswordHash},
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use zeroize::{Zeroize, Zeroizing};
use thiserror::Error;

// ============================================================================
// Error Types - Production error handling
// ============================================================================

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault not found at path: {0}")]
    VaultNotFound(String),
    
    #[error("Invalid password")]
    InvalidPassword,
    
    #[error("Entry '{0}' not found")]
    EntryNotFound(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed - data may be corrupted")]
    DecryptionFailed,
    
    #[error("Invalid vault format: {0}")]
    InvalidFormat(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Vault is locked")]
    VaultLocked,
}

// ============================================================================
// Data Structures
// ============================================================================

/// Each entry file is self-contained with its own encryption parameters
#[derive(Serialize, Deserialize)]
struct EntryFile {
    version: u32,
    /// Unique salt for this specific entry
    salt: String,
    /// Password verification hash for this entry
    verification: String,
    /// The encrypted data
    data: Vec<u8>,
    /// Nonce used for encryption
    nonce: [u8; 12],
    /// Entry metadata
    created_at: u64,
    #[serde(default)]
    accessed_at: Option<u64>,
}

/// Vault metadata stored in config file
#[derive(Serialize, Deserialize, Default)]
struct VaultMetadata {
    created_at: u64,
    modified_at: u64,
    access_count: u64,
}

/// Simple config file - just metadata, no cryptographic material
#[derive(Serialize, Deserialize)]
struct VaultConfig {
    version: u32,
    #[serde(default)]
    metadata: VaultMetadata,
}

// ============================================================================
// Main Vault Implementation
// ============================================================================

pub struct Vault {
    path: PathBuf,
    password: SecretString,
    metadata: VaultMetadata,
    metadata_dirty: bool,
}

impl Vault {
    const CURRENT_VERSION: u32 = 1;
    const CONFIG_FILE: &'static str = ".vault_config";
    const ENTRY_EXTENSION: &'static str = "ventry";
    
    /// Create a new vault directory (fails if already exists)
    pub fn create<P: AsRef<Path>>(path: P, password: &mut SecretString) -> Result<Self, VaultError> {
        let vault_dir = path.as_ref().to_path_buf();

        let mut vault_config_file = vault_dir.clone();
        vault_config_file.push(Self::CONFIG_FILE);
        
        if vault_config_file.exists() {
            return Err(VaultError::InvalidFormat(
                "Vault already exists. Use open() instead.".to_string()
            ));
        }
        
        Self::validate_password(&mut password.clone())?;
        
        // Create vault directory
        fs::create_dir_all(&vault_dir)?;
        Self::set_secure_permissions(&vault_dir)?;
        
        let now = Self::timestamp();
        let metadata = VaultMetadata {
            created_at: now,
            modified_at: now,
            access_count: 0,
        };
        
        let vault = Self {
            path: vault_dir,
            password: password.clone(),
            metadata,
            metadata_dirty: true,
        };
        
        vault.save_config()?;
        password.zeroize();
        
        Ok(vault)
    }
    
    /// Open an existing vault directory
    pub fn open<P: AsRef<Path>>(path: P, password: &mut SecretString) -> Result<Self, VaultError> {
        let vault_dir = path.as_ref().to_path_buf();
        let mut config_file = vault_dir.clone();
        config_file.push(Self::CONFIG_FILE);
        
        if !vault_dir.exists() || !config_file.exists(){
            return Err(VaultError::VaultNotFound(vault_dir.display().to_string()));
        }
        
        Self::verify_permissions(&vault_dir)?;
        Self::validate_password(&mut password.clone())?;
        
        // Read config file
        let config_path = vault_dir.join(Self::CONFIG_FILE);
        let data = fs::read_to_string(&config_path)
            .context("Failed to read vault config file")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let config: VaultConfig = serde_json::from_str(&data)
            .context("Failed to parse vault config")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        if config.version != Self::CURRENT_VERSION {
            return Err(VaultError::InvalidFormat(
                format!("Unsupported vault version: {}", config.version)
            ));
        }
        
        let mut metadata = config.metadata;
        metadata.access_count += 1;
        
        Ok(Self {
            path: vault_dir,
            password: password.clone(),
            metadata,
            metadata_dirty: true,
        })
    }
    
    /// Create or open a vault
    pub fn open_or_create<P: AsRef<Path>>(path: P, password: &mut SecretString) -> Result<Self, VaultError> {
        let vault_dir = path.as_ref().to_path_buf();

        let mut vault_config_file = vault_dir.clone();
        vault_config_file.push(Self::CONFIG_FILE);
        
        if vault_config_file.exists() {
            Self::open(vault_dir, password)
        } else {
            Self::create(vault_dir, password)
        }
    }
    
    /// Store raw bytes as a separate encrypted file with unique salt
    pub fn store_bytes(&mut self, name: &str, data: &[u8]) -> Result<(), VaultError> {
        Self::validate_entry_name(name)?;
        
        // Generate unique salt for this entry
        let salt = SaltString::generate(&mut Argon2Rng);
        
        // Derive key specific to this entry
        let key = Self::derive_key(&mut self.password.clone(), &salt)?;
        
        // Create verification hash for this entry
        let verification = Self::create_verification(&mut self.password.clone(), &salt)?;
        
        // Encrypt with entry-specific key
        let cipher = ChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        // Create self-contained entry file
        let entry_file = EntryFile {
            version: Self::CURRENT_VERSION,
            salt: salt.to_string(),
            verification: verification.to_string(),
            data: encrypted,
            nonce: nonce_bytes,
            created_at: Self::timestamp(),
            accessed_at: None,
        };
        
        // Write entry to its own file
        let entry_path = self.get_entry_path(name);
        let json = serde_json::to_string_pretty(&entry_file)
            .context("Failed to serialize entry")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let mut file = File::create(&entry_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        
        Self::set_secure_permissions(&entry_path)?;
        
        self.metadata.modified_at = Self::timestamp();
        self.metadata_dirty = true;
        
        Ok(())
    }
    
    /// Store a string
    pub fn store_string(&mut self, name: &str, text: &str) -> Result<(), VaultError> {
        self.store_bytes(name, text.as_bytes())
    }
    
    /// Retrieve and decrypt data from file using its own salt/verification
    pub fn get(&mut self, name: &str) -> Result<SecretBox<[u8]>, VaultError> {
        let entry_path = self.get_entry_path(name);
        
        if !entry_path.exists() {
            return Err(VaultError::EntryNotFound(name.to_string()));
        }
        
        // Read encrypted entry from file
        let data = fs::read_to_string(&entry_path)
            .context("Failed to read entry file")
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        let mut entry_file: EntryFile = serde_json::from_str(&data)
            .context("Failed to parse entry file")
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        if entry_file.version != Self::CURRENT_VERSION {
            return Err(VaultError::InvalidFormat(
                format!("Unsupported entry version: {}", entry_file.version)
            ));
        }
        
        // Parse this entry's salt and verification
        let salt = SaltString::from_b64(&entry_file.salt)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid salt: {}", e)))?;
        
        let verification = PasswordHash::new(&entry_file.verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid verification: {}", e)))?;
        
        // Verify password against this entry's verification hash
        Argon2::default()
            .verify_password(self.password.expose_secret().as_bytes(), &verification)
            .map_err(|_| VaultError::InvalidPassword)?;
        
        // Derive key specific to this entry
        let key = Self::derive_key(&mut self.password.clone(), &salt)?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        let nonce = Nonce::from_slice(&entry_file.nonce);
        
        let decrypted = cipher
            .decrypt(nonce, entry_file.data.as_ref())
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        // Update access time
        entry_file.accessed_at = Some(Self::timestamp());
        let json = serde_json::to_string_pretty(&entry_file)
            .context("Failed to serialize entry")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let mut file = File::create(&entry_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        
        Ok(SecretSlice::new(decrypted.into()))
    }
    
    /// Retrieve as string
    pub fn get_string(&mut self, name: &str) -> Result<String, VaultError> {
        let data = self.get(name)?;
        String::from_utf8(data.expose_secret().to_vec())
            .map_err(|e| VaultError::InvalidFormat(format!("Not valid UTF-8: {}", e)))
    }
    
    /// Check if entry exists
    pub fn contains(&self, name: &str) -> bool {
        self.get_entry_path(name).exists()
    }
    
    /// List all entry names by reading directory
    pub fn list(&self) -> Vec<String> {
        let mut entries = Vec::new();
        
        if let Ok(dir_entries) = fs::read_dir(&self.path) {
            for entry in dir_entries.flatten() {
                if let Some(name) = Self::entry_name_from_path(&entry) {
                    entries.push(name);
                }
            }
        }
        
        entries.sort();
        entries
    }
    
    /// Delete an entry file
    pub fn delete(&mut self, name: &str) -> Result<(), VaultError> {
        let entry_path = self.get_entry_path(name);
        
        if !entry_path.exists() {
            return Err(VaultError::EntryNotFound(name.to_string()));
        }
        
        fs::remove_file(entry_path)?;
        
        self.metadata.modified_at = Self::timestamp();
        self.metadata_dirty = true;
        
        Ok(())
    }
    
    /// Get entry metadata without decrypting
    pub fn get_metadata(&self, name: &str) -> Option<EntryInfo> {
        let entry_path = self.get_entry_path(name);
        
        if !entry_path.exists() {
            return None;
        }
        
        let data = fs::read_to_string(&entry_path).ok()?;
        let entry: EntryFile = serde_json::from_str(&data).ok()?;
        
        Some(EntryInfo {
            name: name.to_string(),
            created_at: entry.created_at,
            accessed_at: entry.accessed_at,
            size: entry.data.len(),
        })
    }
    
    /// Change vault password - re-encrypts all entry files with new unique salts
    pub fn change_password(&mut self, old_password: &mut SecretString, new_password: &mut SecretString) -> Result<(), VaultError> {
        Self::validate_password(&mut new_password.clone())?;
        
        let entries = self.list();
        
        // Verify old password works on at least one entry (if any exist)
        if !entries.is_empty() {
            let test_entry_path = self.get_entry_path(&entries[0]);
            let data = fs::read_to_string(&test_entry_path)?;
            let test_file: EntryFile = serde_json::from_str(&data)
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            let salt = SaltString::from_b64(&test_file.salt)
                .map_err(|e| VaultError::InvalidFormat(format!("Invalid salt: {}", e)))?;
            let verification = PasswordHash::new(&test_file.verification)
                .map_err(|e| VaultError::InvalidFormat(format!("Invalid verification: {}", e)))?;
            
            Argon2::default()
                .verify_password(old_password.expose_secret().as_bytes(), &verification)
                .map_err(|_| VaultError::InvalidPassword)?;
        }
        
        old_password.zeroize();
        
        // Re-encrypt each entry with new password and NEW unique salt
        for name in entries {
            let entry_path = self.get_entry_path(&name);
            let data = fs::read_to_string(&entry_path)?;
            let old_entry: EntryFile = serde_json::from_str(&data)
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            // Decrypt with old entry's key
            let old_salt = SaltString::from_b64(&old_entry.salt)
                .map_err(|e| VaultError::InvalidFormat(format!("Invalid salt: {}", e)))?;
            let old_key = Self::derive_key(&mut self.password.clone(), &old_salt)?;
            let old_cipher = ChaCha20Poly1305::new_from_slice(&*old_key)
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            let nonce = Nonce::from_slice(&old_entry.nonce);
            let decrypted = old_cipher
                .decrypt(nonce, old_entry.data.as_ref())
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            // Generate NEW unique salt for this entry with new password
            let new_salt = SaltString::generate(&mut Argon2Rng);
            let new_key = Self::derive_key(&mut new_password.clone(), &new_salt)?;
            let new_verification = Self::create_verification(&mut new_password.clone(), &new_salt)?;
            
            // Encrypt with new key
            let new_cipher = ChaCha20Poly1305::new_from_slice(&*new_key)
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
            
            let mut new_nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut new_nonce_bytes);
            let new_nonce = Nonce::from_slice(&new_nonce_bytes);
            
            let encrypted = new_cipher
                .encrypt(new_nonce, decrypted.as_ref())
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
            
            let new_entry = EntryFile {
                version: Self::CURRENT_VERSION,
                salt: new_salt.to_string(),
                verification: new_verification.to_string(),
                data: encrypted,
                nonce: new_nonce_bytes,
                created_at: old_entry.created_at,
                accessed_at: old_entry.accessed_at,
            };
            
            // Write re-encrypted entry back to file
            let json = serde_json::to_string_pretty(&new_entry)
                .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
            
            let mut file = File::create(&entry_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        
        // Update vault password
        self.password = new_password.clone();
        new_password.zeroize();
        self.metadata_dirty = true;
        
        Ok(())
    }
    
    /// Save vault configuration
    fn save_config(&self) -> Result<(), VaultError> {
        let config = VaultConfig {
            version: Self::CURRENT_VERSION,
            metadata: VaultMetadata {
                created_at: self.metadata.created_at,
                modified_at: Self::timestamp(),
                access_count: self.metadata.access_count,
            },
        };
        
        let json = serde_json::to_string_pretty(&config)
            .context("Failed to serialize vault config")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let config_path = self.path.join(Self::CONFIG_FILE);
        let mut file = File::create(&config_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        
        Self::set_secure_permissions(&config_path)?;
        
        Ok(())
    }
    
    // ========================================================================
    // Helper Methods
    // ========================================================================
    
    fn get_entry_path(&self, name: &str) -> PathBuf {
        self.path.join(format!("{}.{}", name, Self::ENTRY_EXTENSION))
    }
    
    fn entry_name_from_path(entry: &DirEntry) -> Option<String> {
        let path = entry.path();
        
        // Skip config file
        if path.file_name()? == Self::CONFIG_FILE {
            return None;
        }
        
        // Check extension
        if path.extension()? != Self::ENTRY_EXTENSION {
            return None;
        }
        
        path.file_stem()?.to_str().map(String::from)
    }
    
    // ========================================================================
    // Security Utilities
    // ========================================================================
    
    fn derive_key(password: &mut SecretString, salt: &SaltString) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.expose_secret().as_bytes(), salt)
            .map_err(|e| VaultError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;

        password.zeroize();
        
        let hash_bytes = hash.hash
            .ok_or_else(|| VaultError::EncryptionFailed("No hash generated".to_string()))?;
        
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        
        Ok(key)
    }
    
    fn create_verification(password: &mut SecretString, salt: &SaltString) -> Result<String, VaultError> {
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.expose_secret().as_bytes(), salt)
            .map_err(|e| VaultError::EncryptionFailed(format!("Verification failed: {}", e)))?;
        password.zeroize();

        let hash_string = hash.to_string();
        
        Ok(hash_string)
    }
    
    fn validate_password(password: &mut SecretString) -> Result<(), VaultError> {
        if password.expose_secret().len() < 8 {
            return Err(VaultError::InvalidFormat(
                "Password must be at least 8 characters".to_string()
            ));
        }
        password.zeroize();
        Ok(())
    }
    
    fn validate_entry_name(name: &str) -> Result<(), VaultError> {
        if name.is_empty() || name.len() > 255 {
            return Err(VaultError::InvalidFormat(
                "Entry name must be 1-255 characters".to_string()
            ));
        }
        
        if name.contains('\0') || name.contains('/') || name.contains('\\') || name.contains('.') {
            return Err(VaultError::InvalidFormat(
                "Entry name contains invalid characters".to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(unix)]
    fn set_secure_permissions(path: &Path) -> Result<(), VaultError> {
        use std::os::unix::fs::PermissionsExt;
        
        let metadata = fs::metadata(path)?;
        let mut permissions = metadata.permissions();
        
        if metadata.is_dir() {
            permissions.set_mode(0o700); // rwx------
        } else {
            permissions.set_mode(0o600); // rw-------
        }
        
        fs::set_permissions(path, permissions)?;
        Ok(())
    }
    
    #[cfg(not(unix))]
    fn set_secure_permissions(_path: &Path) -> Result<(), VaultError> {
        // On Windows, use ACLs in production
        Ok(())
    }
    
    #[cfg(unix)]
    fn verify_permissions(path: &Path) -> Result<(), VaultError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        let mode = metadata.permissions().mode();
        
        if mode & 0o077 != 0 {
            eprintln!("Warning: Vault permissions are too open ({}). Should be 0700.", mode & 0o777);
        }
        
        Ok(())
    }
    
    #[cfg(not(unix))]
    fn verify_permissions(_path: &Path) -> Result<(), VaultError> {
        Ok(())
    }
    
    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// Auto-save config on drop
impl Drop for Vault {
    fn drop(&mut self) {
        if self.metadata_dirty {
            let _ = self.save_config();
        }
    }
}

// ============================================================================
// Public API Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub name: String,
    pub created_at: u64,
    pub accessed_at: Option<u64>,
    pub size: usize,
}