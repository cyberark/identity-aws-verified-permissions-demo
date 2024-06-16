import argparse
import os
import webbrowser
from getpass import getpass
from pprint import pprint

import requests
from jose import jwt

from utils.utils import check_authorization_with_token

parser = argparse.ArgumentParser()
parser.add_argument(
    '-i',
    '--identity_url',
    required=True,
    help=
    'Identity URL to login path.e.g "https://<customer_id>.my.dev.idaptive.app/<app_id>>'
)

parser.add_argument(
    '-a',
    '--app_id',
    required=True,
    help=
    'Identity app_id path.e.g "https://<customer_id>.my.dev.idaptive.app/<app_id>>'
)

parser.add_argument('-c',
                    required=True,
                    help='Client ID to request access/id token')

parser.add_argument('-s',
                    required=True,
                    help='Client Secret to request access/id token')

parser.add_argument('-psi',
                    required=True,
                    help='Policy Store for ID Token Authorization')

parser.add_argument('-psa',
                    required=True,
                    help='Policy Store for Access Token Authorization')

parser.add_argument('-region', required=False, help='Policy Store region')

args = parser.parse_args()

# Get the client secret from command line arguments or environment variables
client_secret = args.s
if not client_secret:
    client_secret = os.environ.get("CLIENT_SECRET")
if not client_secret:
    client_secret = getpass("Enter user password: ")

# Replace these with your client ID and client secret
client_id = args.c

# Token endpoint
identity_url = args.identity_url
application_id = args.app_id
token_url = f"{identity_url}/OAuth2/Token/{application_id}"

# Authorization endpoint
authorization_url = f"{identity_url}/OAuth2/Authorize/{application_id}"

callback_url = "http://localhost:5000/callback"  # this is the redirect url to the local server to print the authorization code


def exchange_code_for_token(code):
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": callback_url,
        "client_id": client_id,
        "client_secret": client_secret
    }
    token_response = requests.post(token_url, data=token_payload)
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    id_token = token_data.get("id_token")
    return access_token, id_token


def encode_base_64(str_to_encode):
    """ encode base 64 """
    import base64

    str_bytes = str_to_encode.encode('ascii')
    base64_bytes = base64.b64encode(str_bytes)
    return base64_bytes.decode('ascii')


def main():


    authorization_redirect_url = f"{authorization_url}?response_type=code&client_id={client_id}&redirect_uri={callback_url}&scope=openid profile"
    print("Authorization URL:", authorization_redirect_url)
    webbrowser.open(authorization_redirect_url)

    # Manually input the authorization code after authentication
    code = input("Enter the authorization code: ")

    # Exchange authorization code for access token and ID token
    access_token, id_token = exchange_code_for_token(code)

    print("Access token:", access_token)
    print("ID token:", id_token)

    claims = jwt.get_unverified_claims(id_token)
    print('id token claims')
    pprint(claims)

    claims = jwt.get_unverified_claims(access_token)
    print('access token claims')
    pprint(claims)

    # test claim as json
    session_config_json_claim = claims['session_config_json']
    print(f'session config uses as json: {session_config_json_claim}')

    # test claim as long
    session_time_long_claim = claims['session_time_long']
    session_time = int(session_time_long_claim)
    print(
        f'session time uses as long: {session_time}, bit length: {session_time.bit_length()}'
    )

    if args.region:
        region = args.region
    else:
        region = 'us-east-1'

    id_token_policy_store_id = args.psi
    access_token_policy_store_id = args.psa

    action = "View"
    try:
        print('Authorizing with ID Token...')
        decision = check_authorization_with_token(
            region=region,
            id_token=id_token,
            policy_store_id=id_token_policy_store_id,
            action=action)
        print(f'Authorization decision: {decision}')

        print('Authorizing with Access Token...')
        decision = check_authorization_with_token(
            region=region,
            access_token=id_token,
            policy_store_id=access_token_policy_store_id,
            action=action)
        print(f'Authorization decision: {decision}')

    except Exception as e:
        print(f'Error: {e}')


if __name__ == "__main__":
    main()
