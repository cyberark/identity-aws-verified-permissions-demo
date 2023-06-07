#!/usr/bin/python3
import argparse
import json
from http import HTTPStatus
from typing import Dict

import requests
from jose import jwt
from requests_oauth2client import OAuth2Client

HTTP_VERY_LONG_TIMEOUT = 300
identity_headers = {'Content-Type': 'application/json', 'X-IDAP-NATIVE-CLIENT': 'true'}

def get_identity_user_attributes(tenant_url: str, token: str, user_id: str) -> Dict:
    # Get User attributes
    payload = {'Table': 'users', 'ID': user_id}
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    url = f'{tenant_url}ExtData/GetColumns'
    response = requests.request(method='POST', url=url, json=payload, headers=headers)
    if response.status_code == HTTPStatus.OK:
        user_attributes = json.loads(response.text)['Result']
        return user_attributes

def identity_login(identity_url: str, username: str, password: str) -> str:
    try:
        oauth2client = OAuth2Client(
            token_endpoint=f"{identity_url}/oauth2/platformtoken",
            auth=(username, password),
        )
        token = oauth2client.client_credentials(scope="", resource="")
        return str(token)
    except (Exception) as ex:
        print(ex)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user')
    parser.add_argument('-p', '--password')
    parser.add_argument('-i', '--identity_url')
    parser.add_argument('-g', '--gw_url')
    args = parser.parse_args()

    # login and get token
    token = identity_login(username=args.user, password=args.password, identity_url=args.identity_url)
    print(f'user token: {token}')

    # get user id from claims
    claims = jwt.get_unverified_claims(token)

    user_id = claims['sub']
    print (f'user id: {user_id}')
    print (f'user claims are: {claims}')


    # get user attributes
    attributes = get_identity_user_attributes(tenant_url=args.identity_url, token = token , user_id = user_id)
    print (f'user attributes: {attributes}')

    # call api gateway resource, protected by token authorizer and Amazon Verified Permissions as the decision service
    print('invoking the resource rest endpoint...')
    url = f'{args.gw_url}/protected-resource'
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.api.post(url, json={}, headers=headers)

    # verifying and analyzing the result
    if response.status_code == HTTPStatus.OK:
        print(f'you are authorized')
    elif response.status_code == HTTPStatus.FORBIDDEN:
        print(f'you are not authorized')
    else:
        print(f'unexpected error occurred: {response.status_code}')

    print(f'api response is\n{response.text}\n')

if __name__ == "__main__":
    main()
