"""
Zero-Knowledge Proof Authentication Module
Schnorr Protocol + Fiat-Shamir Heuristic
"""

import hashlib
import secrets
import json
import os
from typing import Dict, Tuple

PARAMS_FILE = os.path.join(os.path.dirname(__file__), "zkp_params.json")

class SchnorrZKP:
    def __init__(self, bits: int = 2048):
        self.bits = bits
        self.p, self.q, self.g = self._load_or_generate_parameters()

    def _load_or_generate_parameters(self) -> Tuple[int, int, int]:
        # ── Load existing params if saved ──
        if os.path.exists(PARAMS_FILE):
            print("♻️  Loading saved ZKP parameters...")
            with open(PARAMS_FILE, 'r') as f:
                d = json.load(f)
            p, q, g = int(d['p']), int(d['q']), int(d['g'])
            print("✅ ZKP parameters loaded from disk")
            return p, q, g

        # ── Generate fresh params (first run only) ──
        print(f"⚙️  Generating ZKP parameters ({self.bits} bits)...")
        q = self._generate_prime(self.bits // 2)
        p = 2 * q + 1
        while True:
            h = secrets.randbelow(p - 2) + 2
            g = pow(h, 2, p)
            if pow(g, q, p) == 1 and g != 1:
                break

        # ── Save for all future restarts ──
        with open(PARAMS_FILE, 'w') as f:
            json.dump({'p': str(p), 'q': str(q), 'g': str(g)}, f)
        print(f"✅ ZKP parameters generated and saved to {PARAMS_FILE}")
        return p, q, g

    def _generate_prime(self, bits: int) -> int:
        while True:
            candidate = secrets.randbits(bits)
            candidate |= (1 << bits - 1) | 1
            if self._is_prime(candidate):
                return candidate

    def _is_prime(self, n: int, k: int = 20) -> bool:
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1: continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else:
                return False
        return True

    def register_user(self, password: str) -> Dict:
        salt = secrets.token_hex(32)
        secret = self._derive_secret(password, salt)
        public_key = pow(self.g, secret, self.p)
        return {
            'salt': salt,
            'public_key': str(public_key),
            'params': {
                'p': str(self.p),
                'q': str(self.q),
                'g': str(self.g)
            }
        }

    def _derive_secret(self, password: str, salt: str) -> int:
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations=100000,
            dklen=32
        )
        secret = int.from_bytes(key, 'big') % (self.q - 1) + 1
        return secret

    def generate_challenge(self) -> int:
        return secrets.randbelow(self.q - 1) + 1

    def verify_proof(self, proof: Dict, public_key: int,
                     challenge: int, params: Dict) -> bool:
        try:
            t = int(proof['commitment'])
            s = int(proof['response'])
            p = int(params['p'])
            q = int(params['q'])
            g = int(params['g'])

            # g^s * y^c mod p  ≟  t
            left = (pow(g, s, p) * pow(public_key, challenge, p)) % p
            result = left == t
            if not result:
                print(f"❌ ZKP math failed: g^s*y^c={str(left)[:30]}... t={str(t)[:30]}...")
            return result
        except (KeyError, TypeError, ValueError) as e:
            print(f"❌ Proof verification error: {e}")
            return False


_zkp_instance = None

def get_zkp() -> SchnorrZKP:
    global _zkp_instance
    if _zkp_instance is None:
        _zkp_instance = SchnorrZKP(bits=2048)
    return _zkp_instance

# Global instance
zkp = get_zkp()