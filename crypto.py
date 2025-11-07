#!/usr/bin/env python3
"""
VPN Encryption - Handles all cryptographic operations for the VPN.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import os
from dotenv import load_dotenv
from constants import GCM_NONCE_SIZE, AES_KEY_SIZE


class VPNCrypto:
    """Handles encryption/decryption for VPN packets using AES-256-GCM."""
    
    
    def __init__(self, key_hex=None):
        """
        Initialize crypto with encryption key.
        
        Args:
            key_hex: Hex-encoded 32-byte key. If None, loads from ENCRYPTION_KEY env var
            
        Raises:
            ValueError: If key is missing, invalid, or wrong size
        """
        load_dotenv()
        
        key_hex = key_hex or os.getenv('ENCRYPTION_KEY')
        if not key_hex or key_hex == 'changeme_generate_a_real_key_with_command_above':
            raise ValueError(
                "ENCRYPTION_KEY not set in .env! "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != AES_KEY_SIZE:
            raise ValueError(
                f"Encryption key must be {AES_KEY_SIZE} bytes ({AES_KEY_SIZE*2} hex chars), "
                f"got {len(key_bytes)} bytes"
            )
        
        self.cipher = AESGCM(key_bytes)
        
    def encrypt(self, plaintext):
        """
        Encrypt packet with AES-GCM.
        
        Args:
            plaintext: Raw packet bytes to encrypt
            
        Returns:
            bytes: nonce (12 bytes) + ciphertext + authentication tag (16 bytes)
        """
        nonce = secrets.token_bytes(GCM_NONCE_SIZE)
        ciphertext = self.cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data):
        """
        Decrypt packet with AES-GCM.
        
        Args:
            encrypted_data: nonce + ciphertext + tag
            
        Returns:
            bytes: Decrypted plaintext packet
            
        Raises:
            ValueError: If encrypted data is too short or authentication fails
        """
        if len(encrypted_data) < GCM_NONCE_SIZE:
            raise ValueError("Encrypted data too short")
        
        nonce = encrypted_data[:GCM_NONCE_SIZE]
        ciphertext = encrypted_data[GCM_NONCE_SIZE:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext


def generate_key():
    """
    Generate a random 256-bit encryption key.
    
    Returns:
        str: Hex-encoded 32-byte key suitable for ENCRYPTION_KEY env var
    """
    return secrets.token_hex(AES_KEY_SIZE)


if __name__ == "__main__":
    # Generate a new key if run directly
    print("Generated encryption key:")
    print(generate_key())
    print("\nAdd this to your .env file as:")
    print("ENCRYPTION_KEY=<key_above>")
