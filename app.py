import hashlib
import urllib.parse
import jwt
from flask import Flask, redirect, request, session
import requests
from flask_caching import Cache
import secrets
import base64
from jwt import PyJWKClient, PyJWTError

# Set up the app and cache
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)

# Server settings
server_ip = '127.0.0.1'
server_port = '5000'
server_base_url = f'http://{server_ip}:{server_port}'

# Keycloak settings
keycloak_ip = '127.0.0.1'
keycloak_port = '8080'
keycloak_base_url = f'http://{keycloak_ip}:{keycloak_port}'

# Client and audience
client_id = "flamingo"
client_secret = "JA6fsQdvAemxApJFpfThfhMPAFGDZ6o1"
audience = client_id


# Home route - nothing special here really
@app.route('/')
def home():
    return '<a href="/login">Login</a>'


# Login route
@app.route('/login')
def login():

    # Creating the state
    state = secrets.token_urlsafe(42)

    # Create the code verifier
    code_verifier = secrets.token_urlsafe(42)
    code_verifier_bytes = code_verifier.encode()

    # Create the code challenge
    code_challenge = hashlib.sha256(code_verifier_bytes).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode()

    # Setting up the parameters
    parameters = {
        "client_id": client_id,
        "scope": "openid email phone address profile",
        "response_type": "code",
        "redirect_uri": f"{server_base_url}/callback",
        "prompt": "login",
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }

    # Cache the state and code verifier
    cache.set(state, code_verifier)

    # Forge the redirect url
    authorization_endpoint = f"{keycloak_base_url}/realms/master/protocol/openid-connect/auth"
    return redirect(f"{authorization_endpoint}?{urllib.parse.urlencode(parameters)}")


# Callback route
@app.route('/callback')
def callback():
    # Get the state and code from the request
    state = request.args.get('state')
    code = request.args.get('code')

    # Setting up the parameters
    parameters = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{server_base_url}/callback",
        "code_verifier": cache.get(state),
        "client_id": client_id,
        "client_secret": client_secret
    }

    token_endpoint = f"{keycloak_base_url}/realms/master/protocol/openid-connect/token"
    qs = urllib.parse.urlencode(parameters)

    payload = requests.post(f"{token_endpoint}?{qs}", data=parameters).json()

    # Validate ID token
    id_token = payload["id_token"]
    jwks_client = PyJWKClient(f'{keycloak_base_url}/realms/master/protocol/openid-connect/certs')
    signing_key = jwks_client.get_signing_key_from_jwt(token=id_token)

    try:
        data = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=['RS256'],
            audience=audience
        )

        if data is None:
            print("ID token is invalid!")
            return

        print("ID token is valid!")
    except PyJWTError as e:
        print(f"ID token is invalid: {e}")

    # Fetch user info
    headers = {"Authorization": f"Bearer {payload['access_token']}"}
    content = requests.get(f'{keycloak_base_url}/realms/master/protocol/openid-connect/userinfo', headers=headers).json()

    # Store the cookie
    session['AuthToken'] = payload['access_token']

    return content


# Run the server
if __name__ == '__main__':
    app.run(server_ip, int(server_port), debug=True)
