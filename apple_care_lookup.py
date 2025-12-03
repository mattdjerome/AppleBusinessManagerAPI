import datetime as dt
import uuid
from authlib.jose import jwt  # pip install Authlib
import requests
import time
import csv
import sys
from datetime import datetime

# Get the current date and time
now = datetime.now()
start_time_hh_mm = now.strftime("%H:%M")
print(f"Start Time: {start_time_hh_mm}")

# remove "EC" from the private key and set these:
scope = 'business'  # or 'school'
private_key_file = sys.argv[3]
client_id = sys.argv[1]
key_id = sys.argv[2]

base_url = f'https://api-{scope}.apple.com'
session = requests.Session()  # always use a session for better performance.

def main():
    session.headers['authorization'] = 'Bearer ' + get_token()
    rows = []
    counter = 1

    for device in get_objects('/v1/orgDevices'):
        serial = device['id']
        model = device['attributes'].get('deviceModel', '')
        # Default values
        applecare_desc = ''
        applecare_start = ''
        applecare_end = ''
        # There may be multiple coverages, so collect the latest (if any)
        coverages = list(get_objects(f'/v1/orgDevices/{serial}/appleCareCoverage'))
        if coverages:
            # If multiple, pick the one with the latest endDateTime
            latest = max(coverages, key=lambda c: c['attributes'].get('endDateTime', '') or '')
            applecare_desc = latest['attributes'].get('description', '')
            applecare_start = latest['attributes'].get('startDateTime', '')
            applecare_end = latest['attributes'].get('endDateTime', '')
        row = {
            'SerialNumber': serial,
            'Model': model,
            'AppleCareDescription': applecare_desc,
            'AppleCarestartDateTime': applecare_start,
            'AppleCareEndDateTime': applecare_end
        }
        rows.append(row)
        print(counter, serial, model, applecare_desc, applecare_end)
        counter += 1

    # Write all rows at once
    fieldnames = ['SerialNumber', 'Model', 'AppleCareDescription', 'AppleCareStartDateTime', 'AppleCareEndDateTime']
    export_csv('all_devices.csv', rows, fieldnames)

    # Print end time and duration
    now = datetime.now()
    end_time_hh_mm = now.strftime("%H:%M")
    print(f"End Time: {end_time_hh_mm}")

def get_objects(url):
    while url:
        response = get(url)
        body = response.json()
        for obj in body['data']:
            yield obj
        url = body['links'].get('next')

def get(url):
    if not url.startswith(base_url):
        url = base_url + url
    while True:
        response = session.get(url)
        if response.status_code == requests.codes.too_many_requests:
            time.sleep(int(response.headers.get('retry-after')))
        elif response.status_code == requests.codes.unauthorized:
            session.headers['authorization'] = 'Bearer ' + get_token()
        else:
            return response

def export_csv(filename, rows, fieldnames):
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

def get_token():
    header = {
        'alg': 'ES256',
        'kid': key_id
    }
    issued_at_timestamp = int(dt.datetime.now().timestamp())
    payload = {
        'sub': client_id,
        'aud': 'https://account.apple.com/auth/oauth2/v2/token',
        'iat': issued_at_timestamp,
        'exp': issued_at_timestamp + 86400*180,  # max 180 days
        'jti': str(uuid.uuid4()),
        'iss': client_id
    }
    with open(private_key_file) as file:
        private_key = file.read()
    client_assertion = jwt.encode(header, payload, private_key).decode()
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': client_assertion,
        'scope': f'{scope}.api'
    }
    response = requests.post('https://account.apple.com/auth/oauth2/token', data)
    return response.json()['access_token']

if __name__ == "__main__":
    main()
