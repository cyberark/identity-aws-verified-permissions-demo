#!/usr/bin/python3
import argparse
from getpass import getpass
from pprint import pprint

from jose import jwt

from utils.utils import check_authorization, check_authorization_with_token, cognito_login

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', required=True, help = 'CyberArk Identity user name')
    parser.add_argument('-s', '--policy_store_id', required=True, help = 'Amazon Verified Permisssions  policy store id')
    parser.add_argument('-c', '--client_id', required=True, help = 'AWS Cognito Client Id')
    parser.add_argument('-r', '--region_name', required=True, help = 'AWS resion name. e.g us-east-1')
    args = parser.parse_args()
    password = getpass("Enter user password:")

    # Call the function
    response = cognito_login(user_name= args.user, password=password, client_id = args.client_id, region = args.region_name)
    print(f"response is:{response}")

    if 'AuthenticationResult' in response and response['AuthenticationResult'] and response['AuthenticationResult']['IdToken']:
        token = response['AuthenticationResult']['IdToken']
        claims = jwt.get_unverified_claims(token)
    else:
        exit(0)

    # get user id from claims
    user_id = claims['sub']

    print(f'User id: {user_id}')
    print('User token claims:')
    pprint(claims)

    try:
        policyStoreID = args.policy_store_id

        action = "read"
        print(f'Checking authorization (with principal) on user {user_id} for action {action} @policy store {policyStoreID}')
        decision = check_authorization(policy_store_id=policyStoreID,
                                       principal_id=user_id,
                                       action=action)
        print(f'Authorization decision: {decision}')

        print(f'Checking authorization (with token) on user {user_id} for action {action} @policy store {policyStoreID}')
        decision = check_authorization_with_token(policy_store_id=policyStoreID,
                                                  oidc_token=token,
                                                  action='read')
        print(f'Authorization decision: {decision}')

        print(f'Authorization decision: {decision}')
    except Exception as e:
        print(f'Error: {e}')


if __name__ == '__main__':
    main()
