import os
import base64
import json
import secrets
import time
from typing import Set, Optional, Dict, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
from contextlib import contextmanager
import logging

import requests
from requests.adapters import HTTPAdapter, Retry
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION AND VALIDATION
# ============================================================================

@dataclass(frozen=True)
class SecureStorageConfig:
    """Immutable configuration for secure storage."""
    
    gist_id: Optional[str]
    gist_token: Optional[str]
    encryption_key: Optional[str]
    request_timeout: int = 15
    max_retries: int = 3
    backoff_factor: float = 1.0
    
    @classmethod
    def from_env(cls) -> 'SecureStorageConfig':
        """Create configuration from environment variables."""
        return cls(
            gist_id=os.getenv("GIST_ID", "").strip() or None,
            gist_token=os.getenv("GIST_TOKEN"),
            encryption_key=os.getenv("ENCRYPTION_KEY"),
            request_timeout=int(os.getenv("STORAGE_TIMEOUT", "15")),
            max_retries=int(os.getenv("STORAGE_MAX_RETRIES", "3")),
            backoff_factor=float(os.getenv("STORAGE_BACKOFF_FACTOR", "1.0"))
        )
    
    def validate(self) -> tuple[bool, list[str]]:
        """Validate configuration and return (is_valid, errors)."""
        errors = []
        
        if self.gist_id and self.gist_token:
            if len(self.gist_id) < 10:
                errors.append("GIST_ID appears invalid (too short)")
            
            if len(self.gist_token) < 20:
                errors.append("GIST_TOKEN appears invalid (too short)")
        else:
            errors.append("Both GIST_ID and GIST_TOKEN must be provided")
        
        if self.encryption_key:
            if len(self.encryption_key) < 32:
                errors.append("ENCRYPTION_KEY must be at least 32 characters")
        else:
            errors.append("ENCRYPTION_KEY is required")
        
        if self.request_timeout <= 0 or self.request_timeout > 60:
            errors.append("Request timeout must be between 1-60 seconds")
        
        return len(errors) == 0, errors
    
    @property
    def gist_enabled(self) -> bool:
        """Check if Gist storage is properly configured."""
        return bool(self.gist_id and self.gist_token)
    
    @property
    def encryption_enabled(self) -> bool:
        """Check if encryption is properly configured."""
        return bool(self.encryption_key)


# ============================================================================
# CRYPTOGRAPHIC OPERATIONS
# ============================================================================

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class CryptoManager:
    """Handles all cryptographic operations with secure key derivation."""
    
    # Constants for security
    KEY_LENGTH = 32  # AES-256
    IV_LENGTH = 12   # GCM recommended
    SALT_LENGTH = 32
    KDF_ITERATIONS = 100_000  # OWASP recommended minimum
    
    def __init__(self, password: str):
        """Initialize with password/key string."""
        if not password or len(password) < 8:
            raise CryptoError("Password must be at least 8 characters")
        
        self._password = password
        self._derived_key = None
        self._salt = None
    
    def _get_or_derive_key(self) -> bytes:
        """Get cached key or derive new one."""
        if self._derived_key is None:
            self._derived_key = self._derive_key()
        return self._derived_key
    
    def _derive_key(self) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        try:
            # Try to decode as base64 first (for backward compatibility)
            decoded = base64.b64decode(self._password)
            if len(decoded) == self.KEY_LENGTH:
                logger.info("Using provided base64 key")
                return decoded
        except Exception:
            pass
        
        # Derive key from password
        if self._salt is None:
            # For deterministic key derivation, use hash of password as salt
            # In production, consider storing salt separately
            salt_source = f"c4a-alerts-{self._password}".encode()
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(salt_source)
            self._salt = digest.finalize()[:self.SALT_LENGTH]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=self._salt,
            iterations=self.KDF_ITERATIONS,
            backend=default_backend()
        )
        
        derived_key = kdf.derive(self._password.encode())
        logger.info("Key derived successfully using PBKDF2")
        return derived_key
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return base64 encoded JSON."""
        if not plaintext:
            return json.dumps({"data": ""})
        
        try:
            key = self._get_or_derive_key()
            iv = secrets.token_bytes(self.IV_LENGTH)
            
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()
            
            ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            
            encrypted_data = {
                "version": "1",  # For future migration compatibility
                "iv": base64.b64encode(iv).decode('ascii'),
                "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
                "tag": base64.b64encode(encryptor.tag).decode('ascii')
            }
            
            return json.dumps(encrypted_data, separators=(',', ':'))
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise CryptoError(f"Encryption failed: {e}")
    
    def decrypt(self, encrypted_json: str) -> str:
        """Decrypt base64 encoded JSON and return plaintext."""
        if not encrypted_json:
            return "[]"
        
        try:
            data = json.loads(encrypted_json)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in encrypted data: {e}")
            return "[]"
        
        # Handle unencrypted legacy data
        if isinstance(data, dict) and "data" in data and "iv" not in data:
            logger.warning("Found unencrypted legacy data")
            return data["data"]
        
        # Validate encrypted data structure
        required_fields = {"iv", "ciphertext", "tag"}
        if not all(field in data for field in required_fields):
            logger.error("Invalid encrypted data structure")
            return "[]"
        
        try:
            key = self._get_or_derive_key()
            iv = base64.b64decode(data["iv"])
            ciphertext = base64.b64decode(data["ciphertext"])
            tag = base64.b64decode(data["tag"])
            
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = plaintext_bytes.decode('utf-8')
            
            # Validate that result is valid JSON
            parsed = json.loads(plaintext)
            if not isinstance(parsed, list):
                logger.warning("Decrypted data is not a list, resetting")
                return "[]"
            
            return plaintext
            
        except (InvalidTag, ValueError, json.JSONDecodeError) as e:
            logger.error(f"Decryption failed: {e}")
            return "[]"
        except Exception as e:
            logger.error(f"Unexpected decryption error: {e}")
            return "[]"


# ============================================================================
# HTTP CLIENT WITH RESILIENCE
# ============================================================================

class ResilientHttpClient:
    """HTTP client with retries, timeouts, and circuit breaker pattern."""
    
    def __init__(self, config: SecureStorageConfig):
        self.config = config
        self._session = None
        self._create_session()
    
    def _create_session(self) -> None:
        """Create HTTP session with retry strategy."""
        self._session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "PATCH", "PUT"],
            raise_on_status=False
        )
        
        # Add retry adapter
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        
        # Set default headers
        self._session.headers.update({
            "User-Agent": "C4A-Alerts/4.0 SecureStorage",
            "Accept": "application/vnd.github.v3+json"
        })
    
    def get(self, url: str, headers: Dict[str, str] = None) -> requests.Response:
        """Make GET request with error handling."""
        return self._request("GET", url, headers=headers)
    
    def patch(self, url: str, json_data: Dict[str, Any], headers: Dict[str, str] = None) -> requests.Response:
        """Make PATCH request with error handling."""
        return self._request("PATCH", url, json=json_data, headers=headers)
    
    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with comprehensive error handling."""
        try:
            response = self._session.request(
                method=method,
                url=url,
                timeout=self.config.request_timeout,
                **kwargs
            )
            
            # Log rate limit info if present
            if "X-RateLimit-Remaining" in response.headers:
                remaining = response.headers["X-RateLimit-Remaining"]
                logger.debug(f"GitHub API rate limit remaining: {remaining}")
            
            return response
            
        except requests.exceptions.Timeout:
            raise ConnectionError(f"Request timed out after {self.config.request_timeout}s")
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"HTTP request failed: {e}")
    
    def close(self) -> None:
        """Close the session."""
        if self._session:
            self._session.close()


# ============================================================================
# STORAGE ABSTRACTION
# ============================================================================

class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def load(self) -> Set[str]:
        """Load data and return as set."""
        pass
    
    @abstractmethod
    def save(self, data: Set[str]) -> bool:
        """Save data set and return success status."""
        pass


class GistStorageBackend(StorageBackend):
    """GitHub Gist storage backend with encryption."""
    
    def __init__(self, config: SecureStorageConfig):
        self.config = config
        self.crypto = CryptoManager(config.encryption_key) if config.encryption_enabled else None
        self.http_client = ResilientHttpClient(config)
        
        # Validate configuration
        is_valid, errors = config.validate()
        if not is_valid:
            raise ValueError(f"Invalid configuration: {'; '.join(errors)}")
        
        self.gist_url = f"https://api.github.com/gists/{config.gist_id}"
        self.headers = {
            "Authorization": f"token {config.gist_token}"
        }
    
    def load(self) -> Set[str]:
        """Load sent IDs from encrypted Gist."""
        logger.info("Loading sent IDs from Gist...")
        
        try:
            response = self.http_client.get(self.gist_url, headers=self.headers)
            response.raise_for_status()
            
            gist_data = response.json()
            files = gist_data.get("files", {})
            
            # Try different possible filenames
            content = None
            for filename in ["alerts.json", "sent_ids.json", "history.json"]:
                if filename in files:
                    content = files[filename].get("content", "[]")
                    break
            
            if content is None:
                logger.warning("No alert data file found in Gist")
                return set()
            
            # Decrypt if encryption is enabled
            if self.crypto:
                plaintext = self.crypto.decrypt(content)
            else:
                plaintext = content
            
            # Parse and validate
            try:
                ids_list = json.loads(plaintext)
                if not isinstance(ids_list, list):
                    logger.error("Loaded data is not a list, resetting")
                    return set()
                
                ids_set = set(ids_list)
                logger.info(f"✅ Loaded {len(ids_set)} sent IDs from Gist")
                return ids_set
                
            except json.JSONDecodeError:
                logger.error("Failed to parse loaded data as JSON")
                return set()
            
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning("Gist not found, starting with empty ID set")
            else:
                logger.error(f"HTTP error loading from Gist: {e}")
            return set()
        except ConnectionError as e:
            logger.error(f"Connection error loading from Gist: {e}")
            return set()
        except Exception as e:
            logger.error(f"Unexpected error loading from Gist: {e}")
            return set()
    
    def save(self, ids: Set[str]) -> bool:
        """Save sent IDs to encrypted Gist."""
        logger.info(f"Saving {len(ids)} sent IDs to Gist...")
        
        try:
            # Convert to JSON
            ids_list = sorted(list(ids))  # Sort for deterministic output
            plaintext = json.dumps(ids_list, separators=(',', ':'))
            
            # Encrypt if encryption is enabled
            if self.crypto:
                content = self.crypto.encrypt(plaintext)
            else:
                content = plaintext
            
            # Prepare Gist update payload
            payload = {
                "files": {
                    "alerts.json": {
                        "content": content
                    }
                }
            }
            
            response = self.http_client.patch(self.gist_url, json_data=payload, headers=self.headers)
            response.raise_for_status()
            
            logger.info(f"✅ Successfully saved {len(ids)} IDs to Gist")
            return True
            
        except requests.HTTPError as e:
            logger.error(f"HTTP error saving to Gist: {e}")
            return False
        except ConnectionError as e:
            logger.error(f"Connection error saving to Gist: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error saving to Gist: {e}")
            return False


class FallbackStorageBackend(StorageBackend):
    """Local file storage as fallback."""
    
    def __init__(self, filepath: str = "data/sent_ids.json"):
        self.filepath = filepath
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    def load(self) -> Set[str]:
        """Load from local file."""
        try:
            if not os.path.exists(self.filepath):
                return set()
            
            with open(self.filepath, 'r') as f:
                ids_list = json.load(f)
            
            if isinstance(ids_list, list):
                return set(ids_list)
            else:
                return set()
                
        except Exception as e:
            logger.error(f"Error loading from fallback storage: {e}")
            return set()
    
    def save(self, ids: Set[str]) -> bool:
        """Save to local file."""
        try:
            ids_list = sorted(list(ids))
            with open(self.filepath, 'w') as f:
                json.dump(ids_list, f, separators=(',', ':'))
            return True
        except Exception as e:
            logger.error(f"Error saving to fallback storage: {e}")
            return False


# ============================================================================
# MAIN SECURE STORAGE INTERFACE
# ============================================================================

class SecureStorage:
    """Main interface for secure alert ID storage with multiple backends."""
    
    def __init__(self, config: Optional[SecureStorageConfig] = None):
        self.config = config or SecureStorageConfig.from_env()
        self.backends = []
        
        # Add primary backend (Gist)
        if self.config.gist_enabled:
            try:
                gist_backend = GistStorageBackend(self.config)
                self.backends.append(("gist", gist_backend))
                logger.info("✅ Gist storage backend initialized")
            except Exception as e:
                logger.error(f"❌ Failed to initialize Gist backend: {e}")
        
        # Add fallback backend (local file)
        fallback_backend = FallbackStorageBackend()
        self.backends.append(("fallback", fallback_backend))
        logger.info("✅ Fallback storage backend initialized")
        
        if not self.backends:
            raise RuntimeError("No storage backends available")
    
    def load_sent_ids(self) -> Set[str]:
        """Load sent IDs from available backends."""
        for backend_name, backend in self.backends:
            try:
                logger.info(f"Attempting to load from {backend_name} backend...")
                ids = backend.load()
                logger.info(f"✅ Successfully loaded {len(ids)} IDs from {backend_name}")
                return ids
            except Exception as e:
                logger.warning(f"⚠️ Failed to load from {backend_name}: {e}")
                continue
        
        logger.warning("All backends failed, starting with empty ID set")
        return set()
    
    def save_sent_ids(self, ids: Set[str]) -> bool:
        """Save sent IDs to all available backends."""
        success_count = 0
        
        for backend_name, backend in self.backends:
            try:
                if backend.save(ids):
                    logger.info(f"✅ Successfully saved to {backend_name}")
                    success_count += 1
                else:
                    logger.warning(f"⚠️ Failed to save to {backend_name}")
            except Exception as e:
                logger.error(f"❌ Error saving to {backend_name}: {e}")
        
        if success_count > 0:
            logger.info(f"Successfully saved to {success_count}/{len(self.backends)} backends")
            return True
        else:
            logger.error("Failed to save to all backends")
            return False
    
    def close(self) -> None:
        """Close all backends and cleanup resources."""
        for backend_name, backend in self.backends:
            if hasattr(backend, 'close'):
                try:
                    backend.close()
                except Exception as e:
                    logger.warning(f"Error closing {backend_name} backend: {e}")


# ============================================================================
# PUBLIC API (BACKWARD COMPATIBILITY)
# ============================================================================

# Global instance for backward compatibility
_storage_instance: Optional[SecureStorage] = None

def _get_storage() -> SecureStorage:
    """Get or create global storage instance."""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = SecureStorage()
    return _storage_instance

def load_sent_ids() -> Set[str]:
    """Load sent IDs (backward compatible API)."""
    return _get_storage().load_sent_ids()

def save_sent_ids(ids: Set[str]) -> None:
    """Save sent IDs (backward compatible API)."""
    success = _get_storage().save_sent_ids(ids)
    if not success:
        logger.warning("Failed to save sent IDs to storage")

# Cleanup function
def cleanup_storage() -> None:
    """Cleanup storage resources."""
    global _storage_instance
    if _storage_instance:
        _storage_instance.close()
        _storage_instance = None


# ============================================================================
# CONTEXT MANAGER FOR RESOURCE MANAGEMENT
# ============================================================================

@contextmanager
def secure_storage_session(config: Optional[SecureStorageConfig] = None):
    """Context manager for secure storage operations."""
    storage = SecureStorage(config)
    try:
        yield storage
    finally:
        storage.close()


# Example usage:
if __name__ == "__main__":
    # Test the secure storage system
    logging.basicConfig(level=logging.INFO)
    
    # Using context manager (recommended)
    with secure_storage_session() as storage:
        # Load existing IDs
        current_ids = storage.load_sent_ids()
        print(f"Loaded {len(current_ids)} existing IDs")
        
        # Add some test IDs
        test_ids = {"test-1", "test-2", "test-3"}
        all_ids = current_ids | test_ids
        
        # Save back
        success = storage.save_sent_ids(all_ids)
        print(f"Save {'succeeded' if success else 'failed'}")
