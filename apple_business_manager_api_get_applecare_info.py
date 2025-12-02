#!/usr/bin/env python3
"""
abm_export.py
Fixes and hardening for ABM/Apple Business Manager API export.

Usage:
  python3 abm_export.py <client_id> <key_id> <private_key_file>

Notes:
- Requires: requests, authlib (pip install requests authlib)
- Writes CSV to desktop (or adjust path)
"""
# Originally written by Gabriel Sroka
# Updated by mjerome to include error checking to try and accomodate for large data sets

import sys
import time
import uuid
import csv
import requests
import datetime as dt
from datetime import datetime
from json import JSONDecodeError
from authlib.jose import jwt  # pip install Authlib

# ----- Config / args -----
if len(sys.argv) < 4:
    print("Usage: python3 abm_export.py <client_id> <key_id> <private_key_file>")
    sys.exit(2)

client_id = sys.argv[1]
key_id = sys.argv[2]
private_key_file = sys.argv[3]
scope = 'business'  # or 'school'
base_url = f'https://api-{scope}.apple.com'

session = requests.Session()
session.headers.update({'Accept': 'application/json'})

# ----- Helpers -----
def now_iso_for_filename():
    return datetime.now().strftime("%Y%m%dT%H%M%S")

def get_token():
    """
    Create and POST client_assertion JWT to Apple's token endpoint and return access_token.
    This function will print diagnostics on failure and exit.
    """
    header = {'alg': 'ES256', 'kid': key_id}
    issued_at = int(dt.datetime.now().timestamp())
    payload = {
        'sub': client_id,
        'aud': 'https://account.apple.com/auth/oauth2/v2/token',
        'iat': issued_at,
        'exp': issued_at + 86400 * 180,
        'jti': str(uuid.uuid4()),
        'iss': client_id
    }

    try:
        with open(private_key_file, 'r') as f:
            private_key = f.read()
    except Exception as e:
        print(f"Failed reading private key file: {e}")
        sys.exit(1)

    # authlib.jwt.encode may return bytes or str depending on version; handle both.
    client_assertion = jwt.encode(header, payload, private_key)
    if isinstance(client_assertion, bytes):
        client_assertion = client_assertion.decode('utf-8')

    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': client_assertion,
        'scope': f'{scope}.api'
    }

    token_url = 'https://account.apple.com/auth/oauth2/token'
    try:
        resp = requests.post(token_url, data=data, timeout=30)
    except Exception as e:
        print(f"Token request failed: {e}")
        sys.exit(1)

    # If non-2xx, show text and exit
    if not (200 <= resp.status_code < 300):
        text = None
        try:
            text = resp.text
        except Exception:
            text = str(resp.status_code)
        print(f"Token endpoint returned {resp.status_code}: {text}")
        sys.exit(1)

    try:
        token_body = resp.json()
    except JSONDecodeError as e:
        print(f"Failed to decode token JSON: {e} -- response text: {resp.text}")
        sys.exit(1)

    if 'access_token' not in token_body:
        print(f"No access_token in token response: {token_body}")
        sys.exit(1)

    return token_body['access_token']

def get(url, max_retries=3):
    """
    GET helper that handles base_url prefixing, 401 refresh, and 429 retry-after.
    Returns a requests.Response (on success) or raises exception on unrecoverable error.
    """
    if not url.startswith(base_url):
        url = base_url + url

    attempt = 0
    while True:
        attempt += 1
        try:
            resp = session.get(url, timeout=60)
        except Exception as e:
            if attempt >= max_retries:
                raise
            time.sleep(1)
            continue

        # 429: too many requests -> respect Retry-After (if present), retry
        if resp.status_code == requests.codes.too_many_requests:
            retry_after = resp.headers.get('Retry-After') or resp.headers.get('retry-after') or "5"
            try:
                wait = int(retry_after)
            except Exception:
                wait = 5
            print(f"429 received. Retrying after {wait}s (attempt {attempt})")
            time.sleep(wait)
            if attempt >= max_retries:
                resp.raise_for_status()
            continue

        # 401: token expired -> refresh token and retry
        if resp.status_code == requests.codes.unauthorized:
            print("401 received. Refreshing token and retrying.")
            token = get_token()
            session.headers.update({'Authorization': f'Bearer {token}'})
            if attempt >= max_retries:
                resp.raise_for_status()
            continue

        # Other non-2xx: raise for caller to handle (or here if transient)
        if not (200 <= resp.status_code < 300):
            # Provide diagnostic text for debugging
            text = resp.text if resp is not None else "<no response>"
            raise Exception(f"GET {url} returned status {resp.status_code}: {text}")

        return resp

def get_objects(url):
    """
    Generator that yields objects from paginated ABM responses.
    Handles cases where body['links'] can be "", [], None, or a dict with 'next'.
    """
    while url:
        resp = get(url)
        try:
            body = resp.json()
        except JSONDecodeError as e:
            print(f"JSON decode error for {url}: {e}; response text: {resp.text}")
            return

        # yield data items (default to empty list if missing)
        for item in body.get('data', []):
            yield item

        links = body.get('links')

        if isinstance(links, dict):
            url = links.get('next')
        else:
            # links may be "", [], None, etc. -> stop pagination
            url = None

def export_csv_stream(filename, fieldnames, row_iterable):
    """
    Open CSV once, write header, stream rows from an iterable of dicts.
    """
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for row in row_iterable:
            writer.writerow(row)

# ----- Main flow -----
def main():
    print(f"Start Time: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
    start_ts = datetime.now()

    # get token and set session header
    token = get_token()
    session.headers.update({'Authorization': f'Bearer {token}'})

    out_filename = f'/Users/{getpass_user()}/Desktop/abm_api_output_{now_iso_for_filename()}.csv'
    # If you prefer a different path, change out_filename variable.

    # CSV fieldnames (consistent keys)
    fieldnames = [
        'SerialNumber',
        'Model',
        'OrderDateTime',
        'AppleCareDescription',
        'AppleCareStartDateTime',
        'AppleCareEndDateTime',
    ]

    def rows_generator():
        counter = 1
        # paginate devices
        for device in get_objects('/v1/orgDevices'):
            # defensive accessors
            dev_id = device.get('id', '<no-id>')
            dev_attrs = device.get('attributes') or {}
            model = dev_attrs.get('deviceModel', '')
            order_dt = dev_attrs.get('orderDateTime', '')

            print(counter, dev_id, model)

            # For each device fetch appleCareCoverage - handle endpoints that may return non-dict `links`
            try:
                for coverage in get_objects(f'/v1/orgDevices/{dev_id}/appleCareCoverage'):
                    # coverage may be missing attributes
                    cov_attrs = coverage.get('attributes') or {}
                    desc = cov_attrs.get('description', '')
                    start = cov_attrs.get('startDateTime', '')
                    end = cov_attrs.get('endDateTime', '')

                    print(' ', dev_id, desc, order_dt, start, end)

                    yield {
                        'SerialNumber': dev_id,
                        'Model': model,
                        'OrderDateTime': order_dt,
                        'AppleCareDescription': desc,
                        'AppleCareStartDateTime': start,
                        'AppleCareEndDateTime': end
                    }
            except Exception as e:
                # Keep going; log device id for debugging
                print(f"UNKNOWN ERROR while processing device {dev_id}: {e}")

            counter += 1

    # write CSV streaming rows (header once)
    try:
        export_csv_stream(out_filename, fieldnames, rows_generator())
        print(f"Wrote output to: {out_filename}")
    except Exception as e:
        print(f"Failed writing CSV: {e}")

    end_ts = datetime.now()
    delta = end_ts - start_ts
    minutes = int(delta.total_seconds() // 60)
    seconds = int(delta.total_seconds() % 60)
    print(f"End Time: {end_ts.isoformat(sep=' ', timespec='seconds')}")
    print(f"Total Run Time: {minutes} minutes {seconds} seconds")

def getpass_user():
    """
    Return a username folder for Desktop path; uses environment fallbacks.
    Use this to build a Desktop path without hardcoding mjerome.
    """
    import os
    # Try common env vars
    for env in ('USER', 'LOGNAME', 'USERNAME'):
        u = os.environ.get(env)
        if u:
            return u
    # Fallback
    return os.path.expanduser("~").split('/')[-1]

if __name__ == '__main__':
    main()
    