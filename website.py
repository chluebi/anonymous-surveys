import json
import os

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
        
        schemas[schema['url']] = schema


@app.route('/<name>')
def main(name):
    if name not in schemas:
        return 'Survey not found'
    
    schema = schemas[name]

    code = request.args.get('code', default=None)
    state = request.args.get('code', default=None)

    named_url = f'{URL}/{name}'

    if code and state:
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
    else:
        return render_template('index.html', url=urllib.parse.quote(named_url), client_id=CLIENT_ID, state='newyork')


app.run(port=36666, debug=True)