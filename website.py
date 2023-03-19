import requests
import json
import urllib.parse
from flask import Flask, render_template, send_from_directory, request

app = Flask(__name__)

with open('config.json', 'r') as f:
    config = json.load(f)

CLIENT_ID = config['client-id']
CLIENT_SECRET = config['client-secret']
URL = config['url']

@app.route('/')
def main():
    code = request.args.get('code', default=None)
    state = request.args.get('code', default=None)

    if code and state:
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
        return r.json()
    else:
        return render_template('index.html', url=urllib.parse.quote(URL), client_id=CLIENT_ID, state='newyork')


app.run(port=36666, debug=True)