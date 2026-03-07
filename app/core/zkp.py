"""
Zero-Knowledge Proof Implementation
Using Schnorr Protocol + Fiat-Shamir Heuristic

CRITICAL: Password NEVER stored, NEVER transmitted
"""

import hashlib
import secrets
from typing import Dict, Tuple
from Crypto.Util.number import getPrime
from passlib.hash import pbkdf2_sha256


class SchnorrZKP:
    """
    Schnorr Zero-Knowledge Proof
    
    How it works:
    1. Registration: password → secret → public_key (stored in DB)
    2. Login: server sends challenge
    3. Client creates proof using secret (WITHOUT revealing it)
    4. Server verifies proof using public_key
    
    Result: Server verifies user knows password WITHOUT seeing it!
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize ZKP parameters
        
        p: large prime number
        q: (p-1)/2 (subgroup)
        g: generator (2)
        """
        print(f"⚙️ Generating ZKP parameters ({key_size} bits)...")
        self.p = getPrime(key_size)
        self.q = (self.p - 1) // 2
        self.g = 2
        print(f"✅ ZKP parameters generated")
    
    def get_parameters(self) -> Dict:
        """
        Get ZKP parameters for storage in database
        """
        return {
            "p": str(self.p),
            "q": str(self.q),
            "g": str(self.g)
        }
    
    def derive_secret_from_password(self, password: str, salt: str) -> int:
        """
        CLIENT-SIDE: Derive secret from password
        
        ⚠️ In production, this happens on CLIENT (browser/app)
        Password NEVER sent to server!
        """
        # Use PBKDF2 for key derivation
        hash_output = pbkdf2_sha256.hash(
            password,
            salt=salt.encode(),
            rounds=100000
        )
        
        # Convert to integer
        secret = int(hashlib.sha256(hash_output.encode()).hexdigest(), 16) % self.q
        return secret
    
    def compute_public_key(self, secret: int) -> int:
        """
        Compute public key from secret
        
        public_key = g^secret mod p
        
        This is stored in database (NOT the secret!)
        """
        return pow(self.g, secret, self.p)
    
    def register_user(self, password: str, salt: str = None) -> Tuple[str, int, Dict]:
        """
        Registration flow
        
        ⚠️ In production:
        - Client generates salt
        - Client derives secret from password
        - Client computes public_key
        - Client sends ONLY (salt, public_key) to server
        - Password NEVER transmitted!
        
        Returns: (salt, public_key, parameters)
        """
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Derive secret (CLIENT-SIDE in production!)
        secret = self.derive_secret_from_password(password, salt)
        
        # Compute public key
        public_key = self.compute_public_key(secret)
        
        # Get parameters
        params = self.get_parameters()
        
        return salt, public_key, params
    
    def generate_challenge(self) -> int:
        """
        SERVER-SIDE: Generate random challenge for login
        """
        return secrets.randbelow(self.q)
    
    def create_proof(self, secret: int, challenge: int) -> Dict:
        """
        CLIENT-SIDE: Create zero-knowledge proof
        
        Schnorr Protocol:
        1. Pick random r
        2. Compute commitment: t = g^r mod p
        3. Compute response: s = r - c*secret mod q
        
        Result: Proof that user knows secret WITHOUT revealing it!
        """
        # Random nonce
        r = secrets.randbelow(self.q)
        
        # Commitment
        t = pow(self.g, r, self.p)
        
        # Fiat-Shamir hash
        c_hash = hashlib.sha256(
            str(challenge).encode() + str(t).encode()
        ).hexdigest()
        c = int(c_hash, 16) % self.q
        
        # Response
        s = (r - c * secret) % self.q
        
        return {
            "commitment": str(t),
            "response": str(s),
            "challenge_used": challenge
        }
    
    def verify_proof(
        self,
        proof: Dict,
        public_key: int,
        challenge: int,
        params: Dict
    ) -> bool:
        """
        SERVER-SIDE: Verify zero-knowledge proof
        
        Check if: g^s * public_key^c == t (mod p)
        
        If true: User knows the password!
        If false: Authentication failed
        
        ✅ Server verifies WITHOUT knowing password!
        """
        try:
            t = int(proof["commitment"])
            s = int(proof["response"])
            
            # Get parameters
            p = int(params["p"])
            q = int(params["q"])
            g = int(params["g"])
            
            # Recompute challenge hash
            c_hash = hashlib.sha256(
                str(challenge).encode() + str(t).encode()
            ).hexdigest()
            c = int(c_hash, 16) % q
            
            # Verify: g^s * public_key^c == t (mod p)
            left_side = (pow(g, s, p) * pow(public_key, c, p)) % p
            
            return left_side == t
        
        except Exception as e:
            print(f"❌ Proof verification error: {e}")
            return False


# Global ZKP instance
zkp = SchnorrZKP()