#!/usr/bin/env python3

# pip install PyJWT cryptography requests
import os, time, uuid, requests, jwt, sys, json
from cryptography.hazmat.primitives import serialization

CLIENT_ID = sys.argv[1]
KEY_ID    = sys.argv[2]
KEY_PATH  = sys.argv[3]
DEVICE_ID = sys.argv[4]
TOKEN_AUD = "https://account.apple.com/auth/oauth2/v2/token"
TOKEN_URL = "https://account.apple.com/auth/oauth2/token"
API_BASE  = "https://api-business.apple.com/v1"

# -------------------------------------------------------------------
# 1) Build client assertion
# -------------------------------------------------------------------

now = int(time.time())
payload = {
    "iss": CLIENT_ID,
    "sub": CLIENT_ID,
    "aud": TOKEN_AUD,
    "iat": now,
    "exp": now + 15 * 60,
    "jti": str(uuid.uuid4()),
}

headers = {"kid": KEY_ID, "alg": "ES256", "typ": "JWT"}

with open(KEY_PATH, "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
    
assertion = jwt.encode(payload, key, algorithm="ES256", headers=headers)

# -------------------------------------------------------------------
# 2) Exchange for access token
# -------------------------------------------------------------------

resp = requests.post(
    TOKEN_URL,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data={
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
        "scope": "business.api",
    },
    timeout=30,
)
resp.raise_for_status()
access_token = resp.json()["access_token"]
print("Token acquired successfully.")

# -------------------------------------------------------------------
# 3) Get AppleCare coverage for the device
# -------------------------------------------------------------------

def get_AppleCare(base,serialNumber,accessToken):
    url = f"{base}/orgDevices/{serialNumber}/appleCareCoverage"
    
    headers = {
        "Authorization": f"Bearer {accessToken}",
        "Accept": "application/json"
    }
    
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    coverage_info = resp.json()
    return coverage_info['data']
url = f"{API_BASE}/orgDevices/{DEVICE_ID}"
appleCare = get_AppleCare(API_BASE, sys.argv[4], access_token)
headers = {
    "Authorization": f"Bearer {access_token}",
    "Accept": "application/json"
}

resp = requests.get(url, headers=headers, timeout=30)
resp.raise_for_status()
coverage_info = resp.json()

print(json.dumps(coverage_info, indent=2))
print(json.dumps(appleCare,indent=2))

