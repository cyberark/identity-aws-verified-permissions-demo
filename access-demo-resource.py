#!/usr/bin/python3
import argparse
from getpass import getpass
from http import HTTPStatus
from pprint import pprint

import requests
from jose import jwt

from utils.utils import get_identity_user_attributes, identity_login


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g',
                        '--gw_url',
                        required=True,
                        help='API Gateway URL')
    parser.add_argument('-u',
                        '--user',
                        required=True,
                        help='Username to login to the resource rest endpoint')
    parser.add_argument('-i',
                        '--identity_url',
                        required=True,
                        help='Identity URL to login')
    args = parser.parse_args()
    password = getpass("Enter user password: ")

    # login with username and password and get token
    token = identity_login(username=args.user,
                           password=password,
                           identity_url=args.identity_url)
    print(f'User token: {token}')

    # get user id from claims
    claims = jwt.get_unverified_claims(token)

    user_id = claims['sub']
    print(f'User id: {user_id}')
    print('User token claims:')
    pprint(claims)

    # get user attributes
    attributes = get_identity_user_attributes(tenant_url=args.identity_url,
                                              token=token,
                                              user_id=user_id)
    print(f'user attributes: {attributes}')

    # call api gateway resource, protected by token authorizer and Amazon Verified Permissions as the decision service
    print('Invoking the resource rest endpoint...')

    # these fixed value were predefined in the cloud formation template
    stage_name = 'test'
    resource_name = 'protected-resource'

    # building the resource url from
    resource_url = f'{args.gw_url}/{stage_name}/{resource_name}'
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.api.post(resource_url,
                                 json={},
                                 headers=headers,
                                 timeout=30)
    print('response code:', response.status_code)
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
