use anyhow::{Context, Result};
use ark_std::rand::RngCore;
use secrecy::{ExposeSecret, SecretBox, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, DirEntry};
use std::io::Write;
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
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault not found at path: {0}")]
    VaultNotFound(String),
    
    #[error("Invalid master password")]
    InvalidMasterPassword,
    
    #[error("Invalid entry password")]
    InvalidEntryPassword,
    
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

/// Each entry has TWO layers of encryption:
/// 1. Master password layer (outer) - proves you have vault access
/// 2. Entry password layer (inner) - proves you have entry access
#[derive(Serialize, Deserialize)]
struct EntryFile {
    version: u32,
    
    // Master password layer
    master_salt: String,
    master_verification: String,
    master_encrypted_data: Vec<u8>,
    master_nonce: [u8; 12],
    
    // Entry metadata (not encrypted)
    created_at: u64,
    #[serde(default)]
    accessed_at: Option<u64>,
}

/// Inner layer - encrypted with entry-specific password
#[derive(Serialize, Deserialize)]
struct EntryInnerLayer {
    entry_salt: String,
    entry_verification: String,
    entry_nonce: [u8; 12],
    data: Vec<u8>,
}

/// Vault config with master password verification
#[derive(Serialize, Deserialize)]
struct VaultConfig {
    version: u32,
    master_salt: String,
    master_verification: String,
    #[serde(default)]
    metadata: VaultMetadata,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
struct VaultMetadata {
    created_at: u64,
    modified_at: u64,
    access_count: u64,
}

// ============================================================================
// Main Vault Implementation
// ============================================================================
#[derive(Clone, Debug)]
pub struct Vault {
    path: PathBuf,
    // NO PASSWORD STORED - must be provided for each operation
    master_salt: String,
    master_verification: String,
    metadata: VaultMetadata,
    metadata_dirty: bool,
}

impl Vault {
    const CURRENT_VERSION: u32 = 1;
    const CONFIG_FILE: &'static str = ".vault_config";
    const ENTRY_EXTENSION: &'static str = "ventry";
    
    /// Create a new vault with a master password
    pub fn create<P: AsRef<Path>>(path: P, master_password: &mut SecretString) -> Result<Self, VaultError> {
        let vault_dir = path.as_ref().to_path_buf();
        let mut vault_config_file = vault_dir.clone();
        vault_config_file.push(Self::CONFIG_FILE);
        
        if vault_config_file.exists() {
            return Err(VaultError::InvalidFormat(
                "Vault already exists. Use open() instead.".to_string()
            ));
        }
        
        Self::validate_password(master_password)?;
        
        // Create vault directory
        fs::create_dir_all(&vault_dir)?;
        Self::set_secure_permissions(&vault_dir)?;
        
        // Generate master salt and verification
        let master_salt = SaltString::generate(&mut Argon2Rng);
        let master_verification = Self::create_verification(master_password, &master_salt)?;
        
        let now = Self::timestamp();
        let metadata = VaultMetadata {
            created_at: now,
            modified_at: now,
            access_count: 0,
        };
        
        let config = VaultConfig {
            version: Self::CURRENT_VERSION,
            master_salt: master_salt.to_string(),
            master_verification: master_verification.clone(),
            metadata: metadata.clone(),
        };
        
        // Save config
        let json = serde_json::to_string_pretty(&config)
            .context("Failed to serialize vault config")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let config_path = vault_dir.join(Self::CONFIG_FILE);
        let mut file = File::create(&config_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Self::set_secure_permissions(&config_path)?;
        
        master_password.zeroize();
        
        Ok(Self {
            path: vault_dir,
            master_salt: master_salt.to_string(),
            master_verification,
            metadata,
            metadata_dirty: true,
        })
    }

    pub fn open_or_create<P: AsRef<Path>>(path: P, master_password: &mut SecretString) -> Result<Self, VaultError>{
        let vault_dir = path.as_ref().to_path_buf();
        let mut vault_config_file = vault_dir.clone();
        vault_config_file.push(Self::CONFIG_FILE);
        if !vault_config_file.exists() {
            Self::create(path, master_password)
        } else {
            Self::open(path, master_password)
        }
    }
    
    /// Open existing vault - verifies master password but doesn't store it
    pub fn open<P: AsRef<Path>>(path: P, master_password: &mut SecretString) -> Result<Self, VaultError> {
        let vault_dir = path.as_ref().to_path_buf();
        let mut config_file = vault_dir.clone();
        config_file.push(Self::CONFIG_FILE);
        
        if !vault_dir.exists() || !config_file.exists(){
            return Err(VaultError::VaultNotFound(vault_dir.display().to_string()));
        }
        
        Self::verify_permissions(&vault_dir)?;
        
        // Read config
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
        
        // Verify master password
        let master_verification = PasswordHash::new(&config.master_verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid verification: {}", e)))?;
        
        Argon2::default()
            .verify_password(master_password.expose_secret().as_bytes(), &master_verification)
            .map_err(|_| VaultError::InvalidMasterPassword)?;
        
        master_password.zeroize();
        
        let mut metadata = config.metadata;
        metadata.access_count += 1;
        
        Ok(Self {
            path: vault_dir,
            master_salt: config.master_salt,
            master_verification: config.master_verification,
            metadata,
            metadata_dirty: true,
        })
    }
    
    /// Store data with two-layer encryption
    /// Requires both master password (proves vault access) and entry password (for this specific entry)
    pub fn store_bytes(
        &mut self,
        name: &str,
        data: &[u8],
        master_password: &mut SecretString,
        entry_password: &mut SecretString,
    ) -> Result<(), VaultError> {
        Self::validate_entry_name(name)?;
        Self::validate_password(entry_password)?;
        
        // Verify master password
        let master_salt = SaltString::from_b64(&self.master_salt)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master salt: {}", e)))?;
        
        let master_verification = PasswordHash::new(&self.master_verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master verification: {}", e)))?;
        
        Argon2::default()
            .verify_password(master_password.expose_secret().as_bytes(), &master_verification)
            .map_err(|_| VaultError::InvalidMasterPassword)?;
        
        // LAYER 2: Encrypt with entry-specific password (inner layer)
        let entry_salt = SaltString::generate(&mut Argon2Rng);
        let entry_key = Self::derive_key(entry_password, &entry_salt)?;
        let entry_verification = Self::create_verification(entry_password, &entry_salt)?;
        
        let entry_cipher = ChaCha20Poly1305::new_from_slice(&*entry_key)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        let mut entry_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut entry_nonce_bytes);
        let entry_nonce = Nonce::from_slice(&entry_nonce_bytes);
        
        let entry_encrypted = entry_cipher
            .encrypt(entry_nonce, data)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        let inner_layer = EntryInnerLayer {
            entry_salt: entry_salt.to_string(),
            entry_verification: entry_verification.clone(),
            entry_nonce: entry_nonce_bytes,
            data: entry_encrypted,
        };
        
        let inner_json = serde_json::to_vec(&inner_layer)
            .context("Failed to serialize inner layer")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        // LAYER 1: Encrypt inner layer with master password (outer layer)
        let master_key = Self::derive_key(master_password, &master_salt)?;
        let master_cipher = ChaCha20Poly1305::new_from_slice(&*master_key)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        let mut master_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut master_nonce_bytes);
        let master_nonce = Nonce::from_slice(&master_nonce_bytes);
        
        let master_encrypted = master_cipher
            .encrypt(master_nonce, inner_json.as_ref())
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        // Create entry file
        let entry_file = EntryFile {
            version: Self::CURRENT_VERSION,
            master_salt: self.master_salt.clone(),
            master_verification: self.master_verification.clone(),
            master_encrypted_data: master_encrypted,
            master_nonce: master_nonce_bytes,
            created_at: Self::timestamp(),
            accessed_at: None,
        };
        
        // Write to disk
        let entry_path = self.get_entry_path(name);
        let json = serde_json::to_string_pretty(&entry_file)
            .context("Failed to serialize entry")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let mut file = File::create(&entry_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Self::set_secure_permissions(&entry_path)?;
        
        master_password.zeroize();
        entry_password.zeroize();
        
        self.metadata.modified_at = Self::timestamp();
        self.metadata_dirty = true;
        
        Ok(())
    }
    
    /// Store string with two passwords
    pub fn store_string(
        &mut self,
        name: &str,
        text: &str,
        master_password: &mut SecretString,
        entry_password: &mut SecretString,
    ) -> Result<(), VaultError> {
        self.store_bytes(name, text.as_bytes(), master_password, entry_password)
    }
    
    /// Retrieve data - requires BOTH passwords
    pub fn get(
        &mut self,
        name: &str,
        master_password: &mut SecretString,
        entry_password: &mut SecretString,
    ) -> Result<SecretBox<[u8]>, VaultError> {
        let entry_path = self.get_entry_path(name);
        
        if !entry_path.exists() {
            return Err(VaultError::EntryNotFound(name.to_string()));
        }
        
        // Read entry file
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
        
        // Verify master password
        let master_salt = SaltString::from_b64(&self.master_salt)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master salt: {}", e)))?;
        
        let master_verification = PasswordHash::new(&self.master_verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master verification: {}", e)))?;
        
        Argon2::default()
            .verify_password(master_password.expose_secret().as_bytes(), &master_verification)
            .map_err(|_| VaultError::InvalidMasterPassword)?;
        
        // LAYER 1: Decrypt outer layer with master password
        let master_key = Self::derive_key(master_password, &master_salt)?;
        let master_cipher = ChaCha20Poly1305::new_from_slice(&*master_key)
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        let master_nonce = Nonce::from_slice(&entry_file.master_nonce);
        let inner_json = master_cipher
            .decrypt(master_nonce, entry_file.master_encrypted_data.as_ref())
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        let inner_layer: EntryInnerLayer = serde_json::from_slice(&inner_json)
            .context("Failed to parse inner layer")
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        // Verify entry password
        let entry_salt = SaltString::from_b64(&inner_layer.entry_salt)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid entry salt: {}", e)))?;
        
        let entry_verification = PasswordHash::new(&inner_layer.entry_verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid entry verification: {}", e)))?;
        
        Argon2::default()
            .verify_password(entry_password.expose_secret().as_bytes(), &entry_verification)
            .map_err(|_| VaultError::InvalidEntryPassword)?;
        
        // LAYER 2: Decrypt inner layer with entry password
        let entry_key = Self::derive_key(entry_password, &entry_salt)?;
        let entry_cipher = ChaCha20Poly1305::new_from_slice(&*entry_key)
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        let entry_nonce = Nonce::from_slice(&inner_layer.entry_nonce);
        let decrypted = entry_cipher
            .decrypt(entry_nonce, inner_layer.data.as_ref())
            .map_err(|_| VaultError::DecryptionFailed)?;
        
        // Update access time
        entry_file.accessed_at = Some(Self::timestamp());
        let json = serde_json::to_string_pretty(&entry_file)
            .context("Failed to serialize entry")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let mut file = File::create(&entry_path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        
        master_password.zeroize();
        entry_password.zeroize();
        
        Ok(SecretSlice::new(decrypted.into()))
    }
    
    /// Retrieve as string
    pub fn get_string(
        &mut self,
        name: &str,
        master_password: &mut SecretString,
        entry_password: &mut SecretString,
    ) -> Result<String, VaultError> {
        let data = self.get(name, master_password, entry_password)?;
        String::from_utf8(data.expose_secret().to_vec())
            .map_err(|e| VaultError::InvalidFormat(format!("Not valid UTF-8: {}", e)))
    }
    
    /// Check if entry exists (no password needed)
    pub fn contains(&self, name: &str) -> bool {
        self.get_entry_path(name).exists()
    }
    
    /// List all entries (no password needed)
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
    
    /// Delete entry (requires master password)
    pub fn delete(&mut self, name: &str, master_password: &mut SecretString) -> Result<(), VaultError> {

        // Verify master password
        let master_verification = PasswordHash::new(&self.master_verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master verification: {}", e)))?;
        
        Argon2::default()
            .verify_password(master_password.expose_secret().as_bytes(), &master_verification)
            .map_err(|_| VaultError::InvalidMasterPassword)?;
        
        let entry_path = self.get_entry_path(name);
        
        if !entry_path.exists() {
            return Err(VaultError::EntryNotFound(name.to_string()));
        }
        
        fs::remove_file(entry_path)?;
        
        master_password.zeroize();
        self.metadata.modified_at = Self::timestamp();
        self.metadata_dirty = true;
        
        Ok(())
    }
    
    /// Change master password - re-encrypts all outer layers
    pub fn change_master_password(
        &mut self,
        old_master: &mut SecretString,
        new_master: &mut SecretString,
    ) -> Result<(), VaultError> {
        Self::validate_password(new_master)?;
        
        // Verify old master password
        let old_master_salt = SaltString::from_b64(&self.master_salt)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master salt: {}", e)))?;
        
        let old_master_verification = PasswordHash::new(&self.master_verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid master verification: {}", e)))?;
        
        Argon2::default()
            .verify_password(old_master.expose_secret().as_bytes(), &old_master_verification)
            .map_err(|_| VaultError::InvalidMasterPassword)?;
        
        let entries = self.list();
        
        // Generate new master salt and verification
        let new_master_salt = SaltString::generate(&mut Argon2Rng);
        let new_master_verification = Self::create_verification(new_master, &new_master_salt)?;
        
        // Re-encrypt each entry's outer layer
        for name in entries {
            let entry_path = self.get_entry_path(&name);
            let data = fs::read_to_string(&entry_path)?;
            let old_entry: EntryFile = serde_json::from_str(&data)
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            // Decrypt outer layer with old master
            let old_master_key = Self::derive_key(old_master, &old_master_salt)?;
            let old_cipher = ChaCha20Poly1305::new_from_slice(&*old_master_key)
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            let nonce = Nonce::from_slice(&old_entry.master_nonce);
            let inner_json = old_cipher
                .decrypt(nonce, old_entry.master_encrypted_data.as_ref())
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            // Re-encrypt with new master password
            let new_master_key = Self::derive_key(new_master, &new_master_salt)?;
            let new_cipher = ChaCha20Poly1305::new_from_slice(&*new_master_key)
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
            
            let mut new_nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut new_nonce_bytes);
            let new_nonce = Nonce::from_slice(&new_nonce_bytes);
            
            let new_encrypted = new_cipher
                .encrypt(new_nonce, inner_json.as_ref())
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
            
            let new_entry = EntryFile {
                version: Self::CURRENT_VERSION,
                master_salt: new_master_salt.to_string(),
                master_verification: new_master_verification.clone(),
                master_encrypted_data: new_encrypted,
                master_nonce: new_nonce_bytes,
                created_at: old_entry.created_at,
                accessed_at: old_entry.accessed_at,
            };
            
            let json = serde_json::to_string_pretty(&new_entry)
                .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
            
            let mut file = File::create(&entry_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        
        // Update vault config
        self.master_salt = new_master_salt.to_string();
        self.master_verification = new_master_verification;
        
        old_master.zeroize();
        new_master.zeroize();
        self.metadata_dirty = true;
        self.save_config()?;
        
        Ok(())
    }
    
    /// Save vault configuration
    fn save_config(&self) -> Result<(), VaultError> {
        let config = VaultConfig {
            version: Self::CURRENT_VERSION,
            master_salt: self.master_salt.clone(),
            master_verification: self.master_verification.clone(),
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
        
        if path.file_name()? == Self::CONFIG_FILE {
            return None;
        }
        
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
        
        let hash_bytes = hash.hash
            .ok_or_else(|| VaultError::EncryptionFailed("No hash generated".to_string()))?;
        
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        
        Ok(key)
    }
    
    fn create_verification(password: &SecretString, salt: &SaltString) -> Result<String, VaultError> {
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.expose_secret().as_bytes(), salt)
            .map_err(|e| VaultError::EncryptionFailed(format!("Verification failed: {}", e)))?;
        
        Ok(hash.to_string())
    }
    
    fn validate_password(password: &SecretString) -> Result<(), VaultError> {
        if password.expose_secret().len() < 8 {
            return Err(VaultError::InvalidFormat(
                "Password must be at least 8 characters".to_string()
            ));
        }
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
            permissions.set_mode(0o700);
        } else {
            permissions.set_mode(0o600);
        }
        
        fs::set_permissions(path, permissions)?;
        Ok(())
    }
    
    #[cfg(not(unix))]
    fn set_secure_permissions(_path: &Path) -> Result<(), VaultError> {
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