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

    state = base64.urlsafe_b64encode(secrets.token_bytes(42))

    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(42))
    code_verifier_bytes = hashlib.sha256(code_verifier).digest()
    code_verifier_base64 = base64.urlsafe_b64encode(code_verifier_bytes)

    parameters = {
        "client_id": "flamingo",
        "scope": "openid email phone address profile",
        "response_type": "code",
        "redirect_uri": "http://127.0.0.1:5000/callback",
        "prompt": "login",
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": code_verifier_base64,
    }

    authorization_endpoint = "http://127.0.0.1:8080/realms/master/protocol/openid-connect/auth"
    redirect_url = f"{authorization_endpoint}?{urllib.parse.urlencode(parameters)}"

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
        "code_verifier": cache.get("code_verifier"),
        "client_id": "flamingo",
        "client_secret": "JA6fsQdvAemxApJFpfThfhMPAFGDZ6o1"
    }

    token_endpoint = "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token"
    qs = urllib.parse.urlencode(parameters)

    payload = requests.post(f"{token_endpoint}?{qs}", data=parameters).json()
    return payload


if __name__ == '__main__':
    app.run()
