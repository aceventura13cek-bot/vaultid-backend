"""
Multi-Factor Authentication (MFA) Module
TOTP (Time-based One-Time Password) implementation
"""

import pyotp
import qrcode
import io
import base64
import hashlib
import secrets
from typing import List, Tuple


class MFAManager:
    """
    Handles TOTP-based MFA and backup codes
    """
    
    @staticmethod
    def generate_totp_secret() -> str:
        """
        Generate random TOTP secret
        
        Returns: Base32-encoded secret
        """
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(email: str, secret: str) -> str:
        """
        Generate QR code for Google Authenticator/Authy
        
        Returns: Base64-encoded PNG image
        """
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=email,
            issuer_name="VaultID"
        )
        
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """
        Verify TOTP code
        
        Args:
            secret: User's TOTP secret
            code: 6-digit code from authenticator app
            
        Returns: True if valid
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # Allow 30s window
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """
        Generate one-time backup codes
        
        Format: XXXX-XXXX-XXXX-XXXX
        
        Returns: List of backup codes
        """
        codes = []
        for _ in range(count):
            code = '-'.join([
                secrets.token_hex(2).upper()
                for _ in range(4)
            ])
            codes.append(code)
        
        return codes
    
    @staticmethod
    def hash_backup_code(code: str) -> str:
        """
        Hash backup code for storage
        
        Only hashes stored, not raw codes!
        """
        return hashlib.sha256(code.encode()).hexdigest()
    
    @staticmethod
    def verify_backup_code(code: str, hashed_codes: List[str]) -> bool:
        """
        Verify backup code against stored hashes
        
        Returns: True if code matches any hash
        """
        code_hash = MFAManager.hash_backup_code(code)
        return code_hash in hashed_codes


# Singleton
mfa_manager = MFAManager()