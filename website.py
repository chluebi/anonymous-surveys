import json
import os
import secrets
import time
import hashlib

import requests
import urllib.parse
from flask import Flask, render_template, send_from_directory, request, make_response, redirect

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

def add_hashed_id(file, hashed_id):
    with open(file, 'r') as f:
        results = json.load(f)

    results['ids-entered'].append({
        'hash':hashed_id
    })

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def get_hashed_id(file, hashed_id):
    with open(file, 'r') as f:
        results = json.load(f)

    for id in results['ids-entered']:
        if id['hash'] == hashed_id:
            return id

    return None


def prune_access_tokens(file):
    with open(file, 'r') as f:
        results = json.load(f)

    nonces = results['access-tokens']
    current_time = time.time()
    new_nonces = list(filter(lambda n: n['expires'] > current_time, nonces))

    results['access-tokens'] = new_nonces

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def add_access_token(file, token, expires):
    with open(file, 'r') as f:
        results = json.load(f)

    results['access-tokens'].append({
        'token': token,
        'expires': expires
    })

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def get_access_token(file, token):
    with open(file, 'r') as f:
        results = json.load(f)

    for stored_token in results['access-tokens']:
        if stored_token['token'] == token:
            return token
        
    return None


@app.route('/')
def main():
    code = request.args.get('code', default=None)
    state = request.args.get('state', default=None)

    if not (code and state):
        return 'Nothing here'

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
    
    schema = correct_schema
    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

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
    
    headers = {
        'Authorization': 'Bearer ' + access_token
    }
    r = requests.get(f'{API_ENDPOINT}/users/@me', headers=headers)
    r.raise_for_status()
    user = r.json()

    id = user['id']

    if schema['guild-only']:
        headers = {
            'Authorization': 'Bearer ' + access_token
        }
        r = requests.get(f'{API_ENDPOINT}/users/@me/guilds', headers=headers)
        r.raise_for_status()
        guilds = r.json()
        
        allowed = False
        for guild in guilds:
            if int(guild['id']) in schema['guilds']:
                allowed = True
                break

        if not allowed:
            return 'You are not allowed to access this survey'
    
    peppered_id = id + config['pepper']
    hashed_id = hashlib.sha256(peppered_id.encode()).hexdigest()

    if get_hashed_id(results_file, hashed_id) is not None:
        return 'You have already filled in this survey'
    
    add_hashed_id(results_file, hashed_id)

    access_token = secrets.token_urlsafe(32)
    expires = int(time.time()+(30*24*60*60))

    add_access_token(results_file, access_token, expires)

    resp = make_response(redirect(URL + '/' + schema['url']))
    resp.set_cookie('token-' + schema['url'], access_token, expires=expires, samesite='Lax')
    return resp


@app.route('/<name>')
def named(name):
    if name not in schemas:
        return 'Survey not found'
    
    schema = schemas[name]

    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

    named_url = f'{URL}/{name}'

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = get_access_token(results_file, token_cookie)

    if token_cookie is not None and stored_token is not None:
        return 'You havez cookie :3'
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