import json
import os
import secrets
import time

import requests
import urllib.parse
from flask import Flask, render_template, send_from_directory, request

app = Flask(__name__)

with open('config.json', 'r') as f:
    config = json.load(f)

CLIENT_ID = config['client-id']
CLIENT_SECRET = config['client-secret']
URL = config['url']


schemas = {}

for folder in os.listdir('data'):
    if not os.path.exists(f'data/{folder}/schema.json'):
        continue

    with open(f'data/{folder}/schema.json') as f:
        schema = json.load(f)
        if not schema['active']:
            continue
        if schema['url'] in schemas:
            raise Exception('conflicting URLs')
        
        schema['folder'] = folder
        schemas[schema['url']] = schema


def prune_state_nonces(file):
    with open(file, 'r') as f:
        results = json.load(f)

    nonces = results['nonces']
    current_time = time.time()
    new_nonces = list(filter(lambda n: n['expires'] > current_time, nonces))

    results['nonces'] = new_nonces

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def add_state_nonce(file, nonce):
    with open(file, 'r') as f:
        results = json.load(f)

    results['nonces'].append(nonce)

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def get_state_nonce(file, state):
    with open(file, 'r') as f:
        results = json.load(f)

    found_nonce = None
    for nonce in results['nonces']:
        if nonce['state'] == state:
            found_nonce = nonce
            break

    return found_nonce

@app.route('/')
def main():
    code = request.args.get('code', default=None)
    state = request.args.get('state', default=None)

    if code and state:
        correct_schema = None
        for _, schema in schemas.items():
            folder_path = 'data/' + schema['folder']
            results_file = f'{folder_path}/results.json'

            prune_state_nonces(results_file)
            if get_state_nonce(results_file, state) is not None:
                correct_schema = schema
                break

        if correct_schema is None:
            return 'Invalid state'

        API_ENDPOINT = 'https://discord.com/api/v10'
        data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': URL
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        r = requests.post(f'{API_ENDPOINT}/oauth2/token', data=data, headers=headers)
        
        r.raise_for_status()
        access = r.json()
        
        access_token = access['access_token']
        print(access_token)
        return 'lol'
    else:
        return 'Nothing here'


@app.route('/<name>')
def named(name):
    print(schemas)
    if name not in schemas:
        return 'Survey not found'
    
    schema = schemas[name]

    code = request.args.get('code', default=None)
    state = request.args.get('state', default=None)

    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

    named_url = f'{URL}/{name}'

    if code and state:
        prune_state_nonces(results_file)
        if get_state_nonce(results_file, state) is None:
            return "Invalid state"

        API_ENDPOINT = 'https://discord.com/api/v10'
        data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': named_url
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        r = requests.post(f'{API_ENDPOINT}/oauth2/token', data=data, headers=headers)
        
        r.raise_for_status()
        access = r.json()
        
        access_token = access['access_token']
        print(access_token)
    else:
        state = secrets.token_urlsafe(16)
        state_nonce = {
            'state':state,
            'expires':time.time()+(60*60) # one hour
        }
        prune_state_nonces(results_file)
        add_state_nonce(results_file, state_nonce)

        return render_template('index.html', url=urllib.parse.quote(URL), client_id=CLIENT_ID, state=state)


app.run(port=36666, debug=True)