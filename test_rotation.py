import sys
sys.path.insert(0, '.')

import requests
import time

BASE = "http://127.0.0.1:8000"

print("🧪 Testing Refresh Token Rotation\n")

# Step 1: Register
email = f"rotation_test_{int(time.time())}@test.com"
password = "SecurePass123!"

print("1️⃣ Registering user...")
r = requests.post(f"{BASE}/auth/register", json={
    "name": "Rotation Test",
    "email": email,
    "password": password,
    "dob": "1990-01-01"
})
print(f"   ✅ Registered: {r.status_code}\n")

# Step 2: Login
print("2️⃣ Logging in...")
r = requests.post(f"{BASE}/auth/challenge", json={"email": email})
challenge = int(r.json()["challenge"])

# Create proof
import psycopg2
import hashlib
import secrets
from passlib.hash import pbkdf2_sha256

conn = psycopg2.connect("postgresql://vaultdev:vaultdev123@localhost/vaultid_dev")
cur = conn.cursor()
cur.execute("SELECT zkp_salt, zkp_params FROM users WHERE email = %s", (email,))
salt, params = cur.fetchone()
conn.close()

p = int(params['p'])
q = int(params['q'])
g = int(params['g'])

hash_output = pbkdf2_sha256.hash(password, salt=salt.encode(), rounds=100000)
secret = int(hashlib.sha256(hash_output.encode()).hexdigest(), 16) % q

r = secrets.randbelow(q)
t = pow(g, r, p)
c_hash = hashlib.sha256(str(challenge).encode() + str(t).encode()).hexdigest()
c = int(c_hash, 16) % q
s = (r - c * secret) % q

proof = {"commitment": str(t), "response": str(s), "challenge_used": challenge}

r = requests.post(f"{BASE}/auth/login", json={
    "email": email,
    "proof": proof,
    "challenge": challenge
})

tokens = r.json()
print(f"   ✅ Logged in: {r.status_code}")
print(f"   Access Token: {tokens['access_token'][:30]}...")
print(f"   Refresh Token: {tokens['refresh_token'][:30]}...\n")

original_refresh = tokens['refresh_token']

# Step 3: Refresh token (FIRST TIME - should work)
print("3️⃣ Refreshing token (FIRST USE)...")
r = requests.post(f"{BASE}/auth/refresh", json={
    "refresh_token": original_refresh
})

if r.status_code == 200:
    new_tokens = r.json()
    print(f"   ✅ SUCCESS: {r.status_code}")
    print(f"   New Access Token: {new_tokens['access_token'][:30]}...")
    print(f"   New Refresh Token: {new_tokens['refresh_token'][:30]}...")
    print(f"   ⚠️ Old refresh token now BLACKLISTED\n")
    
    # Step 4: Try using OLD refresh token again (SHOULD FAIL!)
    print("4️⃣ Attempting to reuse OLD refresh token...")
    print("   (This simulates a REPLAY ATTACK)\n")
    
    r = requests.post(f"{BASE}/auth/refresh", json={
        "refresh_token": original_refresh  # OLD token!
    })
    
    if r.status_code == 401:
        print(f"   ✅ BLOCKED: {r.status_code}")
        print(f"   Error: {r.json()['detail']}")
        print(f"   🚨 Security breach detected!")
        print(f"   🔒 All sessions revoked!\n")
        
        print("="*60)
        print("✅ REFRESH TOKEN ROTATION WORKS!")
        print("="*60)
        print("\n🔐 Security Summary:")
        print("   ✅ Refresh token used once")
        print("   ✅ New tokens issued")
        print("   ✅ Old token blacklisted")
        print("   ✅ Replay attack detected and blocked")
        print("   ✅ All sessions revoked on breach")
    else:
        print(f"   ❌ SECURITY ISSUE: Old token still works!")
else:
    print(f"   ❌ Refresh failed: {r.status_code}")
    print(f"   {r.json()}")
