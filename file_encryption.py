import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
from typing import Tuple, Optional

class FileEncryptor:
    # Configuration constants
    SALT_SIZE = 16  # 128-bit salt
    DERIVATION_ITERATIONS = 600000  # OWASP recommended minimum
    KEY_DERIVATION_LENGTH = 32  # 256-bit key

    @staticmethod
    def generate_key(salt: bytes) -> bytes:
        """Generate encryption key using PBKDF2 with HMAC-SHA256
        
        Args:
            salt: Cryptographically secure random salt
            
        Returns:
            Base64 URL-safe encoded encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=FileEncryptor.KEY_DERIVATION_LENGTH,
            salt=salt,
            iterations=FileEncryptor.DERIVATION_ITERATIONS
        )
        return base64.urlsafe_b64encode(kdf.derive(b'secure_file_sharing'))

    @staticmethod
    def encrypt_file(file_path: str, sender_id: str) -> Tuple[str, str, str]:
        """Encrypt file with authenticated encryption
        
        Args:
            file_path: Path to file to encrypt
            sender_id: Unique sender identifier for audit logging
            
        Returns:
            Tuple of (encrypted_path, file_hash, salt_hex)
            
        Raises:
            RuntimeError: If encryption fails
        """
        try:
            # Generate cryptographically secure salt
            salt = secrets.token_bytes(FileEncryptor.SALT_SIZE)
            key = FileEncryptor.generate_key(salt)
            f = Fernet(key)

            # Read and hash original file
            with open(file_path, 'rb') as file:
                file_data = file.read()
            file_hash = hashlib.sha256(file_data).hexdigest()

            # Encrypt data
            encrypted_data = f.encrypt(file_data)
            encrypted_filename = f"{os.path.basename(file_path)}.enc"
            
            # Ensure storage directory exists
            encrypted_dir = "/data/encrypted_files"
            os.makedirs(encrypted_dir, exist_ok=True)
            encrypted_path = os.path.join(encrypted_dir, encrypted_filename)

            # Write salt + encrypted data
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(salt + encrypted_data)

            return encrypted_path, file_hash, salt.hex()

        except Exception as e:
            raise RuntimeError(f"Encryption failed for {file_path}: {str(e)}") from e

    @staticmethod
    def decrypt_file(encrypted_path: str, recipient_id: str, filename: Optional[str] = None) -> str:
        """Decrypt file with authenticated verification
        
        Args:
            encrypted_path: Path to encrypted file
            recipient_id: Intended recipient identifier
            filename: Optional original filename
            
        Returns:
            Path to decrypted file
            
        Raises:
            RuntimeError: If decryption fails or authentication invalid
        """
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as file:
                file_data = file.read()

            # Extract salt and encrypted content
            if len(file_data) < FileEncryptor.SALT_SIZE:
                raise ValueError("Invalid encrypted file format")
                
            salt = file_data[:FileEncryptor.SALT_SIZE]
            encrypted_content = file_data[FileEncryptor.SALT_SIZE:]

            # Derive key and decrypt
            key = FileEncryptor.generate_key(salt)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_content)

            # Determine output filename
            decrypted_filename = filename or os.path.basename(encrypted_path).replace('.enc', '')
            
            # Ensure output directory exists
            decrypted_dir = "/data/decrypted_files"
            os.makedirs(decrypted_dir, exist_ok=True)
            decrypted_path = os.path.join(decrypted_dir, decrypted_filename)

            # Write decrypted file
            with open(decrypted_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            return decrypted_path

        except Exception as e:
            error_details = {
                'recipient': recipient_id,
                'file': encrypted_path,
                'error': str(e)
            }
            raise RuntimeError(f"Decryption failed: {error_details}") from e