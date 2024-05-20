#!/usr/bin/python3
import argparse
from getpass import getpass
from pprint import pprint

from jose import jwt
from utils.utils import identity_login, check_authorization, check_authorization_with_token

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', required=True, help = 'This is the identity user name')
    parser.add_argument('-i', '--identity_url', required=True ,help='This is the CyberArk identity url')
    parser.add_argument('-a', '--app_id', required=True, help = 'This is the CyberArk identity app id')
    parser.add_argument('-s', '--policy_store_id', required=True, help = 'This is the policy store id')
    args = parser.parse_args()
    password = getpass("Enter your password:")

    # # login with username and password and get token
    token = identity_login(username=args.user, password=password, identity_url=args.identity_url)

    print(f'User token: {token}')

    # get user id from claims
    claims = jwt.get_unverified_claims(token)

    user_id = claims['sub']
    print (f'User id: {user_id}')
    print ('User token claims:')
    pprint(claims)

    try:

        policy_store_id = args.policy_store_id
        action = "read"

        print(f'Checking authorization (with principal) on user {user_id} for action {action} @policy store {policy_store_id}')
        decision = check_authorization(policy_store_id=policy_store_id,
                                        principal_id = user_id,
                                        action = action)
        print (f'Authorization decision: {decision}')


        print(f'Checking authorization (with token) on user {user_id} for action {action} @policy store {policy_store_id}')
        decision = check_authorization_with_token(policy_store_id=policy_store_id,
                                                   oidc_token = token,
                                                   action = action)
        print (f'Authorization decision: {decision}')

    except Exception as e:
        print(f'Error: {e}')

if __name__ == '__main__':
    main()
