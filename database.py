import json
import time
import secrets
import os

from plotting import update_plots

def prune_state_nonces(name):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    nonces = results['nonces']
    current_time = time.time()
    new_nonces = list(filter(lambda n: n['expires'] > current_time, nonces))

    results['nonces'] = new_nonces

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def add_state_nonce(name, nonce):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    results['nonces'].append(nonce)

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def get_state_nonce(name, state):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    found_nonce = None
    for nonce in results['nonces']:
        if nonce['state'] == state:
            found_nonce = nonce
            break

    return found_nonce

def add_hashed_id(name, hashed_id):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    results['ids-entered'].append({
        'hash':hashed_id
    })

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def get_hashed_id(name, hashed_id):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    for id in results['ids-entered']:
        if id['hash'] == hashed_id:
            return id

    return None


def prune_access_tokens(name):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    nonces = results['access-tokens']
    current_time = time.time()
    new_nonces = list(filter(lambda n: n['expires'] > current_time, nonces))

    results['access-tokens'] = new_nonces

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def add_access_token(name, token, expires, permissions):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    results['access-tokens'].append({
        'token': token,
        'expires': expires,
        'permissions': permissions
    })

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def get_access_token(name, token):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    for stored_token in results['access-tokens']:
        if stored_token['token'] == token:
            return stored_token
        
    return None

def remove_access_token(name, token):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    new_access_tokens = []
    for stored_token in results['access-tokens']:
        if stored_token['token'] != token['token']:
            new_access_tokens.append(stored_token)

    results['access-tokens'] = new_access_tokens

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)


def validate_answer(schema, answers):
    questions = schema['questions']
    if len(answers) != len(questions):
        return False

    for answer, question in zip(answers, questions):
        if question['type'] == 'multiple-choice':
            if answer == '':
                if question['options']['canskip'] is False:
                    return False
            elif answer not in question['options']['choices']:
                if question['options']['textother'] is False:
                    return False
                elif len(answer) > 1000:
                    return False
        elif question['type'] == 'text':
            if answer == '':
                if question['options']['canskip'] is False:
                    return False
            elif len(answer) > 1000:
                return False
        else:
            raise Exception('Invalid Question Type')
        
    return True

def secure_shuffle(a):
    b = []
    while len(a) > 0:
        el = secrets.choice(a)
        b.append(el)
        a.remove(el)
    
    return b

def write_answer(name, answer):
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    results['results'].append(answer)
    results['results'] = secure_shuffle(results['results'])

    with open(file, 'w') as f:
        json.dump(results, f, indent=4)



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

        prune_state_nonces(schema['folder'])
        prune_access_tokens(schema['folder'])
        update_plots(schema)