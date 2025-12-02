# pip install PyJWT cryptography requests
import os, time, uuid, requests, jwt, sys,json
from cryptography.hazmat.primitives import serialization

CLIENT_ID = sys.argv[1]   # BUSINESSAPI.xxxxx...
KEY_ID    = sys.argv[2]   # the GUID-like Key ID
KEY_PATH  = sys.argv[3]   # path to PKCS#8 EC P-256 private key

TOKEN_AUD = "https://account.apple.com/auth/oauth2/v2/token"
TOKEN_URL = "https://account.apple.com/auth/oauth2/token"
API_BASE  = "https://api-business.apple.com/v1"

# 1) Build client assertion (ES256, 15 min)
now = int(time.time())
payload = {
    "iss": CLIENT_ID,
    "sub": CLIENT_ID,
    "aud": TOKEN_AUD,
    "iat": now,
    "exp": now + 15*60,
    "jti": str(uuid.uuid4()),
}
headers = {"kid": KEY_ID, "alg": "ES256", "typ": "JWT"}
with open(KEY_PATH, "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)

assertion = jwt.encode(payload, key, algorithm="ES256", headers=headers)

# 2) Exchange for access token
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

# 3) Call the API with pagination and rate-limit handling
all_devices = []
url = f"{API_BASE}/orgDevices"
backoff = 5  # initial backoff in seconds

while url:
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )

    if response.status_code == 429:
        # Rate limit hit
        retry_after = int(response.headers.get("Retry-After", backoff))
        print(f"Rate limit reached. Waiting {retry_after} seconds...")
        time.sleep(retry_after)
        backoff = min(backoff * 2, 300)  # exponential backoff, max 5 min
        continue

    response.raise_for_status()
    data = response.json()

    # Append current page's devices
    if "data" in data:
        all_devices.extend(data["data"])

    # Check if there's a next page
    url = data.get("links", {}).get("next")

    # Reset backoff after successful request
    backoff = 5
    time.sleep(1)  # small delay to avoid hammering the API

print(f"Total devices retrieved: {len(all_devices)}")
for device in all_devices:
    print(device)
with open (f'/Users/mjerome/Desktop/ABM_Warranty_11242025-2.json', 'w') as f:
    json.dump(all_devices,f,indent=4)
