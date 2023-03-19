import requests
import json
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
        return "yes code"
    else:
        return render_template('index.html', url=URL, client_id=CLIENT_ID, state='newyork')


app.run(port=36666, debug=True)