#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys


import os
import requests
import hashlib
import base64
from flask import Flask, redirect, request, render_template

# Spotify API credentials
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
redirect_uri = 'http://127.0.0.1:8888/callback'

# Flask app setup
app = Flask(__name__)


scope = [
    'ugc-image-upload',
    'user-read-playback-state',
    'user-modify-playback-state',
    'user-read-currently-playing',
    'app-remote-control',
    'streaming',
    'playlist-read-private',
    'playlist-read-collaborative',
    'playlist-modify-private',
    'playlist-modify-public',
    'user-follow-modify',
    'user-follow-read',
    'user-read-playback-position',
    'user-top-read',
    'user-read-recently-played',
    'user-library-modify',
    'user-library-read',
    'user-read-email',
    'user-read-private',
]

# Generate random string for state
#state = os.urandom(32)
state='joebiggins'

# Generate code verifier
code_verifier = os.urandom(32)


# Hash code verifier using SHA256
code_challenge = hashlib.sha256(code_verifier).hexdigest()

state_key = 'spotify_auth_state'


# Build and send GET request to /authorize endpoint
@app.route('/login')
def authorize():
    params = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'state': state,
        'scope': ' '.join(scope),
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    url = 'https://accounts.spotify.com/authorize'
    r = requests.get(url, params=params)
    print(r.url)
    return redirect(r.url)


@app.route('/callback', methods=['GET'])
def callback():
    code = request.args.get('code') or None
    state = request.args.get('state') or None
    stored_state = request.cookies.get(state_key) or None

    print('callback......................')
    print(f"code: {code} : {type(code)}")
    
    if state is None:
        return redirect('/#' + urllib.parse.urlencode({'error': 'state_mismatch'}))
    else:
        #request.delete_cookie(state_key)
        client_cred_str = ':'.join([client_id, client_secret])
        as_bytes = bytes(client_cred_str, 'utf-8')
        auth_options = {
            'url': 'https://accounts.spotify.com/api/token',
            'form': {
                'code': code,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code',
                'client_id': client_id,
                'code_verifier': code_verifier
            },
            'headers': {
                'Authorization': 'Basic ' + str(base64.b64encode(as_bytes), 'utf-8')
            },
            'json': True
        }

        print(type(request))
        response = request.post(auth_options)
        if response.status_code == 500:
            access_token = response.body.access_token
            refresh_token = response.body.refresh_token

            options = {
                'url': 'https://api.spotify.com/v1/me',
                'headers': {
                    'Authorization': 'Bearer ' + access_token
                 },
                'json': True
            }

            response = requests.get(options)
            if response.status_code == 200:
                print(response.body)

            return redirect('/#' +  urlencode({
                    'access_token': access_token,
                    'refresh_token': refresh_token
                    }))
        else:
            return redirect('/#' + urlencode({'error': 'invalid_token'}))




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)



