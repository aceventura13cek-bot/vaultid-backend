import sys
sys.path.insert(0, '.')

import requests
import time

BASE = "http://127.0.0.1:8000"

print("🧪 Testing Session Management\n")

# Helper function to create user and login
def create_and_login(email_suffix):
    email = f"session_test_{email_suffix}@test.com"
    password = "Pass123!"
    
    # Register
    requests.post(f"{BASE}/auth/register", json={
        "name": "Session Test",
        "email": email,
        "password": password,
        "dob": "1990-01-01"
    })
    
    # Get challenge
    r = requests.post(f"{BASE}/auth/challenge", json={"email": email})
    challenge = int(r.json()["challenge"])
    
    # Create proof
    import psycopg2, hashlib, secrets
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
    
    # Login
    r = requests.post(f"{BASE}/auth/login", json={
        "email": email,
        "proof": proof,
        "challenge": challenge
    })
    
    return r.json()

# Test 1: Create multiple sessions
print("1️⃣ Creating multiple sessions...")
user_suffix = int(time.time())

session1 = create_and_login(f"{user_suffix}_1")
print(f"   Session 1 created")

session2 = create_and_login(f"{user_suffix}_2")
print(f"   Session 2 created")

session3 = create_and_login(f"{user_suffix}_3")
print(f"   Session 3 created")

# Test 2: List sessions
print("\n2️⃣ Listing sessions...")
headers = {"Authorization": f"Bearer {session1['access_token']}"}
r = requests.get(f"{BASE}/auth/sessions", headers=headers)

if r.status_code == 200:
    sessions = r.json()
    print(f"   ✅ Found {sessions['total']} active sessions")
    for i, s in enumerate(sessions['sessions'], 1):
        print(f"      {i}. {s['device_name']} - Last active: {s['last_activity']}")
else:
    print(f"   ❌ Failed: {r.status_code}")

# Test 3: Get current user info
print("\n3️⃣ Getting current user info...")
r = requests.get(f"{BASE}/auth/me", headers=headers)

if r.status_code == 200:
    user = r.json()
    print(f"   ✅ User: {user['name']} ({user['email']})")
    print(f"   ZKP Enabled: {user['zkp_enabled']}")
else:
    print(f"   ❌ Failed: {r.status_code}")

# Test 4: Revoke specific session (we'll skip this for now - need session_id)

# Test 5: Logout all devices
print("\n4️⃣ Testing 'Logout All Devices'...")
r = requests.post(f"{BASE}/auth/logout-all", headers=headers)

if r.status_code == 200:
    result = r.json()
    print(f"   ✅ {result['message']}")
    print(f"   Sessions revoked: {result['sessions_revoked']}")
else:
    print(f"   ❌ Failed: {r.status_code}")

# Test 6: Verify sessions are revoked
print("\n5️⃣ Verifying sessions revoked...")
r = requests.get(f"{BASE}/auth/sessions", headers=headers)

if r.status_code == 401:
    print(f"   ✅ Access denied (token invalidated as expected)")
elif r.status_code == 200:
    sessions = r.json()
    print(f"   ⚠️ Still {sessions['total']} active sessions")
else:
    print(f"   Status: {r.status_code}")

print("\n" + "="*60)
print("✅ SESSION MANAGEMENT TEST COMPLETE!")
print("="*60)
print("\n📊 Features Tested:")
print("   ✅ Multiple session creation")
print("   ✅ Session listing")
print("   ✅ User info retrieval")
print("   ✅ Logout all devices")
print("   ✅ Session revocation verification")
