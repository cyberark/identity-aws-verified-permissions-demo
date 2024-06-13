import logging
import os
from typing import Dict

from jose import jwt

from utils.utils import (_get_user_attributes, check_authorization,
                         verify_oidc_token_signature)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TENANT_URL = os.environ.get('TENANT_IDENTITY_URL')
POLICY_STORE_ID = os.environ.get('POLICY_STORE_ID')


def lambda_handler(event, context) -> Dict:
    """Authorize user access based on the token information and policies stored at Amazon Verified Permissions
    Parameters:
        event (Dict): A dictionary containing the method arn and authorization token
        (see here: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html)

        context (Lambda Context):  The lambda function context

    Returns:
        IAM policy (Dict): a dictionary representing the IAM policy with the effect (Deny / Allow)

    More info on CyberArk tokens can be found here:
       id tokens - https://identity-developer.cyberark.com/docs/id-tokens
       access tokens - https://identity-developer.cyberark.com/docs/access-tokens
    """

    # Validate oidc token signature and get the claims in the token.
    token = event['authorizationToken'].replace('Bearer', '').strip()

    verify_oidc_token_signature(tenant_url=TENANT_URL, token=token)
    claims = jwt.get_unverified_claims(token)

    # Extract token information
    user_id = claims['sub']
    logger.info(f'principal: {user_id}')

    method_arn = event['methodArn']
    api_gateway_method = method_arn.split(':')[5].split('/')
    logger.info(f'method_arn: {method_arn}')

    # Calculating the action as a concatenation of the rest method and resource name
    method = api_gateway_method[2]
    resource = api_gateway_method[-1]

    # Call Amazon Verified Permissions to authorize. The return value is Allow / Deny and can be assigned to the IAM Policy
    effect = check_authorization(policy_store_id=POLICY_STORE_ID,
                                 principal_id=claims['sub'],
                                 action=method,
                                 resource_id=resource,
                                 token=token)

    # Build the output
    policy_response = generate_iam_policy(principal_id=user_id,
                                          effect=effect,
                                          resource=method_arn)
    logger.info(f'response: {policy_response}')

    return policy_response


def generate_iam_policy(principal_id: str, effect: str, resource: str) -> Dict:
    """
    This method generates the IAM policy to allow / deny access to the Amazon API Gateway resource
    Parameters
        principalId: Principal to validate
        effect (str): Allow or Deny
        resource (str): Name of the API Gateway resource

    :return: Dictionary containing the IAM policy
    """
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version':
            '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }

    return policy
