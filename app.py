import hashlib
import urllib.parse
from flask import Flask, redirect, request
import requests
from flask_caching import Cache
import secrets
import base64


app = Flask(__name__)
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)


@app.route('/')
def home():
    return '<a href="/login">Login</a>'


@app.route('/login')
def login():

    state = secrets.token_urlsafe(42)

    code_verifier = secrets.token_urlsafe(42)
    code_verifier_bytes = code_verifier.encode()

    code_challenge = hashlib.sha256(code_verifier_bytes).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode()

    parameters = {
        "client_id": "flamingo",
        "scope": "openid email phone address profile",
        "response_type": "code",
        "redirect_uri": "http://127.0.0.1:5000/callback",
        "prompt": "login",
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }

    authorization_endpoint = "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth"
    redirect_url = f"{authorization_endpoint}?{urllib.parse.urlencode(parameters)}"
    print(redirect_url)

    cache.set(state, code_verifier)

    return redirect(redirect_url)


@app.route('/callback')
def callback():
    state = request.args.get('state')
    code = request.args.get('code')
    print(code)

    parameters = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://127.0.0.1:5000/callback",
        "code_verifier": cache.get(state),
        "client_id": "flamingo",
        "client_secret": "JA6fsQdvAemxApJFpfThfhMPAFGDZ6o1"
    }

    token_endpoint = "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token"
    qs = urllib.parse.urlencode(parameters)

    payload = requests.post(f"{token_endpoint}?{qs}", data=parameters).json()
    return payload


if __name__ == '__main__':
    app.run('127.0.0.1', 5000, debug=True)
