#!/usr/bin/python3
import os
import datetime as dt
import uuid as uuid
from authlib.jose import jwt
from Crypto.PublicKey import ECC
import sys

private_key_file = sys.argv[1]
client_id = sys.argv[2]
key_id = sys.argv[3]
audience = "https://account.apple.com/auth/oauth2/v2/token"
alg = "ES256"

# Define the issue timestamp.
issued_at_timestamp = int(dt.datetime.utcnow().timestamp())
# Define the expiration timestamp, which may not exceed 180 days from the issue timestamp.
expiration_timestamp = issued_at_timestamp + 86400*180

# Define the JWT headers.
headers = dict()
headers['alg'] = alg
headers['kid'] = key_id

# Define the JWT payload.
payload = dict()
payload['sub'] = client_id
payload['aud'] = audience
payload['iat'] = issued_at_timestamp
payload['exp'] = expiration_timestamp
payload['jti'] = str(uuid.uuid4())
payload['iss'] = client_id

# Open the private key.
with open(private_key_file, 'rt') as file:
    private_key = ECC.import_key(file.read())

# Encode the JWT and sign it with the private key.
client_assertion = jwt.encode(
    header=headers,
    payload=payload,
    key=private_key.export_key(format='PEM')
).decode('UTF-8')

# Save the client assertion to a file.
with open('client_assertion.txt', 'w') as output:
     output.write(client_assertion)
