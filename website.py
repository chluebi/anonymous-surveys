import json
import os
import secrets
import time
import hashlib

import requests
import urllib.parse
from flask import Flask, render_template, send_from_directory, request, make_response, redirect
from waitress import serve


from util import config, URL, CLIENT_ID, CLIENT_SECRET
import database as db
import plotting


app = Flask(__name__)



@app.route('/')
def main():
    code = request.args.get('code', default=None)
    state = request.args.get('state', default=None)

    if not (code and state):
        return 'Nothing here', 404

    correct_schema = None
    for _, schema in db.schemas.items():
        db.prune_state_nonces(schema['folder'])
        if db.get_state_nonce(schema['folder'], state) is not None:
            correct_schema = schema
            break

    if correct_schema is None:
        return 'Invalid state', 404
    
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
            return 'You are not allowed to access this survey', 401
    
    peppered_salted_id = id + config['pepper'] + schema['url']
    hashed_id = hashlib.sha256(peppered_salted_id.encode()).hexdigest()

    if db.get_hashed_id(schema['folder'], hashed_id) is not None:
        return 'You have already filled in this survey', 401
    
    db.add_hashed_id(schema['folder'], hashed_id)

    access_token = secrets.token_urlsafe(32)
    expires = int(time.time()+(30*24*60*60))

    db.prune_access_tokens(schema['folder'])
    db.add_access_token(schema['folder'], access_token, expires)

    resp = make_response(redirect(URL + '/' + schema['url']))
    resp.set_cookie('token-' + schema['url'], access_token, expires=expires, samesite='Lax')
    return resp


@app.route('/<name>')
def named(name):
    if name not in db.schemas:
        return 'Survey not found', 404
    
    schema = db.schemas[name]

    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = db.get_access_token(schema['folder'], token_cookie)

    if token_cookie is None or stored_token is None:
        state = secrets.token_urlsafe(16)
        state_nonce = {
            'state':state,
            'expires':time.time()+(60*60) # one hour
        }
        db.prune_state_nonces(schema['folder'])
        db.add_state_nonce(schema['folder'], state_nonce)

        return render_template('index.html', unparsed_url=URL, url=urllib.parse.quote(URL), client_id=CLIENT_ID, state=state, schema=schema)
    

    return render_template('quiz.html', url=URL, name=name)


@app.route('/<name>/questions')
def questions(name):
    if name not in db.schemas:
        return 'Survey not found', 404
    
    schema = db.schemas[name]

    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = db.get_access_token(schema['folder'], token_cookie)

    if token_cookie is None or stored_token is None:
        return 'Not authorized', 401
    
    return send_from_directory(f'data/{name}','schema.json')


@app.route('/<name>/plot/<plot_id>')
def plot(name, plot_id):
    if name not in db.schemas:
        return 'Survey not found', 404
    
    schema = db.schemas[name]

    if not schema['results-public']:
        folder_path = 'data/' + schema['folder']
        results_file = f'{folder_path}/results.json'

        token_cookie = request.cookies.get('token-' + schema['url'], None)

        stored_token = None
        if token_cookie is not None:
            stored_token = db.get_access_token(schema['folder'], token_cookie)

        if token_cookie is None or stored_token is None:
            return 'Not authorized', 401
        
        if plot_id < 0 or plot_id >= len(schema['questions']):
            return 'Invalid Plot Id', 404
        
        if not os.path.exists(f'data/{name}/plots/{plot_id}.html'):
            return 'Plot should be there, but not found', 500
        
    return send_from_directory(f'data/{name}/plots', f'{plot_id}.html')


@app.route('/<name>/results')
def results(name):
    if name not in db.schemas:
        return 'Survey not found', 404
    
    schema = db.schemas[name]

    if not schema['results-public']:
        folder_path = 'data/' + schema['folder']
        results_file = f'{folder_path}/results.json'

        token_cookie = request.cookies.get('token-' + schema['url'], None)

        stored_token = None
        if token_cookie is not None:
            stored_token = db.get_access_token(schema['folder'], token_cookie)

        if token_cookie is None or stored_token is None:
            return 'Not authorized', 401
    
    plot_folder = f'data/{name}/plots'
    with open(f'{plot_folder}/all.html', 'r') as f:
        plots = f.readlines()

    questions = schema['questions']

    questions_plots = zip(range(0,len(questions)), questions, plots)
        
    return render_template('results.html', url=URL, schema=schema, questions_plots=questions_plots)


@app.route('/<name>/submit', methods=['POST'])
def submit(name):
    if name == 'test':
        return redirect(URL + "/thanks")
    
    if name not in db.schemas:
        return 'Survey not found', 404
    
    schema = db.schemas[name]

    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = db.get_access_token(schema['folder'], token_cookie)

    if token_cookie is None or stored_token is None:
        return 'Not authorized', 401
    
    answer = request.json['answers']
    if not db.validate_answer(schema, answer):
        return 'Invalid answer', 406
    
    db.write_answer(schema['folder'], answer)
    db.remove_access_token(schema['folder'], stored_token)
    plotting.update_plots(schema)
    
    return 'Done', 200


@app.route('/<name>/thanks', methods=['GET'])
def thanks(name):
    return 'Thank you for filling out the survey'

def run():
    if config['debug']:
        app.run(port=36666, debug=True)
    else:
        serve(app, port=36666, url_scheme='https')