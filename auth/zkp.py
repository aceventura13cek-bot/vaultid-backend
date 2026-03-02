import hashlib
import secrets

# Demo-safe prime & generator (NOT production)
p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
g = 2

# ---- Utilities ----
def hash_int(*args):
    h = hashlib.sha256()
    for a in args:
        h.update(str(a).encode())
    return int(h.hexdigest(), 16)

# ---- Registration (demo only) ----
def generate_public_key(secret_x: int):
    return pow(g, secret_x, p)

# ---- Prover side ----
def generate_proof(secret_x: int, public_y: int):
    r = secrets.randbelow(p)
    t = pow(g, r, p)

    c = hash_int(t, public_y) % p
    s = (r + c * secret_x) % (p - 1)

    return {"t": t, "s": s}

# ---- Verifier side ----
def verify_proof(public_y: int, t: int, s: int):
    c = hash_int(t, public_y) % p

    left = pow(g, s, p)
    right = (t * pow(public_y, c, p)) % p

    return left == right
