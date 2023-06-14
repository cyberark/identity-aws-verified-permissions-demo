#!/usr/bin/python3
import argparse
import json
import time
from getpass import getpass
from http import HTTPStatus
from pprint import pprint
from typing import Dict

import requests
from jose import jwt
from requests_oauth2client import OAuth2Client

def get_identity_user_attributes(tenant_url: str, token: str, user_id: str) -> Dict:
    # Get User attributes
    payload = {'Table': 'users', 'ID': user_id}
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
    url = f'{tenant_url}ExtData/GetColumns'
    response = requests.request(method='POST', url=url, json=payload, headers=headers, timeout=30)
    if response.status_code == HTTPStatus.OK:
        user_attributes = json.loads(response.text)['Result']
        return user_attributes
    return None

def identity_login(identity_url: str, username: str, password: str) -> str:
    retries = 0
    while retries < 3:
        try:
            print('identity url:', identity_url)
            oauth2client = OAuth2Client(
                token_endpoint=f'{identity_url}/oauth2/platformtoken',
                auth=(username, password),
                timeout = 10
            )
            token = oauth2client.client_credentials(scope="", resource="")
            return str(token)
        except (Exception) as ex:
            time.sleep(2)
            retries +=1

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user')
    parser.add_argument('-i', '--identity_url')
    parser.add_argument('-g', '--gw_url')
    args = parser.parse_args()

    password = getpass("Enter your password: ")

    # login with username and password and get token
    token = identity_login(username=args.user, password=password, identity_url=args.identity_url)
    print(f'User token: {token}')

    # get user id from claims
    claims = jwt.get_unverified_claims(token)

    user_id = claims['sub']
    print (f'User id: {user_id}')
    print ('User token claims:')
    pprint(claims)

    # get user attributes
    attributes = get_identity_user_attributes(tenant_url=args.identity_url, token=token, user_id=user_id)
    print(f'user attributes: {attributes}')

    # call api gateway resource, protected by token authorizer and Amazon Verified Permissions as the decision service
    print('Invoking the resource rest endpoint...')

    # these fixed value were predefined in the cloud formation template
    stage_name = 'test'
    resource_name = 'protected-resource'

    # building the resource url from
    resource_url = f'{args.gw_url}/{stage_name}/{resource_name}'
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.api.post(resource_url, json={}, headers=headers, timeout=30)
    print ('response code:', response.status_code)
    # verifying and analyzing the result
    if response.status_code == HTTPStatus.OK:
        print('You are authorized')
    elif response.status_code == HTTPStatus.FORBIDDEN:
        print('You are not authorized')
    else:
        print(f'Unexpected error occurred: {response.status_code}')

    print(f'API response: {response.text}')


if __name__ == '__main__':
    main()
