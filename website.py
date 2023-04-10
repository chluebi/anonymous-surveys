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


def login_page(schema):
    state = secrets.token_urlsafe(16)
    state_nonce = {
        'state':state,
        'expires':time.time()+(60*60) # one hour
    }
    db.prune_state_nonces(schema['folder'])
    db.add_state_nonce(schema['folder'], state_nonce)

    return render_template('login.html', unparsed_url=URL, url=urllib.parse.quote(URL), client_id=CLIENT_ID, state=state, schema=schema)


@app.route('/')
def main():
    code = request.args.get('code', default=None)
    state = request.args.get('state', default=None)

    if not (code and state):
        public = []
        for _, schema in db.schemas.items():
            public_levels = ['public', 'log-in']
            if schema['survey'] in public_levels or schema['results'] in public_levels:
                public.append((schema['title'], schema['url']))

        return render_template('index.html', url=URL, public=public)

    correct_schema = None
    for _, schema in db.schemas.items():
        db.prune_state_nonces(schema['folder'])
        if db.get_state_nonce(schema['folder'], state) is not None:
            correct_schema = schema
            break

    if correct_schema is None:
        return render_template('status.html', url=URL, code=404, message='Invalid State'), 404
    
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

    # get guilds
    headers = {
        'Authorization': 'Bearer ' + access_token
    }
    r = requests.get(f'{API_ENDPOINT}/users/@me/guilds', headers=headers)
    r.raise_for_status()
    guilds = r.json()
    
    in_guild = False
    for guild in guilds:
        if int(guild['id']) in schema['guilds']:
            in_guild = True
            break

    
    peppered_salted_id = id + config['pepper'] + schema['url']
    hashed_id = hashlib.sha256(peppered_salted_id.encode()).hexdigest()

    completed = db.get_hashed_id(schema['folder'], hashed_id) is not None
    db.add_hashed_id(schema['folder'], hashed_id)

    access_token = secrets.token_urlsafe(32)
    expires = int(time.time()+(30*24*60*60))

    db.prune_access_tokens(schema['folder'])

    permissions = {'survey': False, 'survey-completed': False, 'results': False, 'results-after': False}

    if schema['survey'] == 'log-in':
        permissions['survey'] = True
    elif schema['survey'] == 'guild-only' and in_guild:
        permissions['survey'] = True
    
    if schema['results'] == 'log-in':
        permissions['results'] = not schema['results-only-after']
        permissions['results-after'] = True
    elif schema['results'] == 'guild-only' and in_guild:
        permissions['results'] = not schema['results-only-after']
        permissions['results-after'] = True

    if schema['results'] == 'public':
        permissions['results'] = True

    if completed:
        permissions['survey-completed'] = True

    db.add_access_token(schema['folder'], access_token, expires, permissions)

    resp = make_response(redirect(URL + '/' + schema['url']))
    resp.set_cookie('token-' + schema['url'], access_token, expires=expires, samesite='Lax')
    return resp


@app.route('/<name>')
def named(name):
    if name not in db.schemas:
        return render_template('status.html', url=URL, code=404, message='Survey Not Found'), 404
    
    schema = db.schemas[name]

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = db.get_access_token(schema['folder'], token_cookie)

    show_survey = False
    survey_completed = False
    show_results = False
    results_login = True

    if token_cookie is None or stored_token is None:
        show_survey = True
        show_results = not schema['results-only-after']
        survey_login = True
        results_login = schema['results'] != 'public'
    else:
        show_survey = stored_token['permissions']['survey']
        show_results = stored_token['permissions']['results']
        survey_completed = stored_token['permissions']['survey-completed']
        survey_login = False
        results_login = False

    if schema['results'] == 'public':
        show_results = True

    return render_template('survey_overview.html', url=URL, name=name, schema=schema,
        show_survey=show_survey, survey_completed=survey_completed,
        show_results=show_results, 
        survey_login=survey_login, results_login=results_login)


@app.route('/<name>/survey')
def survey(name):
    if name not in db.schemas:
        return render_template('status.html', url=URL, code=404, message='Survey Not Found'), 404
    
    schema = db.schemas[name]

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = db.get_access_token(schema['folder'], token_cookie)

    if token_cookie is None or stored_token is None:
        return login_page(schema)
    
    if not stored_token['permissions']['survey']:
        return render_template('status.html', url=URL, code=401, message='You do not have permissions to complete this survey.'), 401

    if stored_token['permissions']['survey-completed']:
        return render_template('status.html', url=URL, code=401, message='You have already completed this survey.'), 401

    return render_template('survey.html', url=URL, name=name)


@app.route('/<name>/questions')
def questions(name):
    if name not in db.schemas:
        return render_template('status.html', url=URL, code=404, message='Survey Not Found'), 404
    
    schema = db.schemas[name]

    folder_path = 'data/' + schema['folder']
    results_file = f'{folder_path}/results.json'

    if not schema['results'] == 'public':
        token_cookie = request.cookies.get('token-' + schema['url'], None)

        stored_token = None
        if token_cookie is not None:
            stored_token = db.get_access_token(schema['folder'], token_cookie)

        if token_cookie is None or stored_token is None:
            return render_template('status.html', url=URL, code=401, message='Not Authorized'), 401

        if not stored_token['permissions']['results'] and not stored_token['permissions']['survey']:
            return render_template('status.html', url=URL, code=401, message='You do not have permissions to complete this survey.'), 401
    
    return send_from_directory(f'data/{name}','schema.json')


@app.route('/<name>/plot/<plot_id>')
def plot(name, plot_id):

    if name not in db.schemas:
        return render_template('status.html', url=URL, code=404, message='Survey Not Found'), 404
    
    schema = db.schemas[name]

    if not schema['results'] == 'public':
        token_cookie = request.cookies.get('token-' + schema['url'], None)

        stored_token = None
        if token_cookie is not None:
            stored_token = db.get_access_token(schema['folder'], token_cookie)

        if token_cookie is None or stored_token is None:
            return login_page(schema)
        
        if not stored_token['permissions']['results']:
            return render_template('status.html', url=URL, code=401, message='You do not have permissions to see this plot.'), 401
        
        if not os.path.exists(f'data/{name}/plots/{plot_id}.html'):
            return render_template('status.html', url=URL, code=404, message='Invalid Plot Id'), 404
        
    return send_from_directory(f'data/{name}/plots', f'{plot_id}.html')


@app.route('/<name>/results')
def results(name):
    if name not in db.schemas:
        return render_template('status.html', url=URL, code=404, message='Survey Not Found'), 404
    
    schema = db.schemas[name]

    if not schema['results'] == 'public':
        folder_path = 'data/' + schema['folder']
        results_file = f'{folder_path}/results.json'

        token_cookie = request.cookies.get('token-' + schema['url'], None)

        stored_token = None
        if token_cookie is not None:
            stored_token = db.get_access_token(schema['folder'], token_cookie)

        if token_cookie is None or stored_token is None:
            return login_page(schema)
        
        if not stored_token['permissions']['results']:
            return render_template('status.html', url=URL, code=401, message='You do not have permissions to see the results of this survey.'), 401
    
    plot_folder = f'data/{name}/plots'
    with open(f'{plot_folder}/all.html', 'r') as f:
        plots = f.readlines()

    enum_plots = enumerate(plots)
        
    return render_template('results.html', url=URL, schema=schema, enum_plots=enum_plots)


@app.route('/<name>/submit', methods=['POST'])
def submit(name):
    if name not in db.schemas:
        return render_template('status.html', url=URL, code=404, message='Survey Not Found'), 404
    
    schema = db.schemas[name]

    token_cookie = request.cookies.get('token-' + schema['url'], None)

    stored_token = None
    if token_cookie is not None:
        stored_token = db.get_access_token(schema['folder'], token_cookie)

    if token_cookie is None or stored_token is None:
        return render_template('status.html', url=URL, code=401, message='Not Authorized'), 401
    
    if not stored_token['permissions']['survey']:
        return render_template('status.html', url=URL, code=401, message='You do not have permissions to complete this survey.'), 401
    
    answer = request.json['answers']
    if not db.validate_answer(schema, answer):
        return render_template('status.html', url=URL, code=406, message='Invalid Answer'), 406
    
    db.write_answer(schema['folder'], answer)
    db.remove_access_token(schema['folder'], stored_token)
    plotting.update_plots(schema)
    
    access_token = secrets.token_urlsafe(32)
    expires = int(time.time()+(365*24*60*60))
    permissions = {'survey': stored_token['permissions']['survey'], 
                   'survey-completed': True,
                   'results': stored_token['permissions']['results'] or stored_token['permissions']['results-after'], 
                   'results-after': stored_token['permissions']['results-after']}

    db.add_access_token(schema['folder'], access_token, expires, permissions)

    cookie = {'name':'token-' + schema['url'],
              'value':access_token,
              'expires':expires}
    
    return cookie, 200


def run():
    if config['debug']:
        app.run(port=36666, debug=True)
    else:
        serve(app, port=36666, url_scheme='https')