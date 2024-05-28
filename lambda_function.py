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


# def _get_user_attributes(tenant_url: str, token: str, user_id: str) -> Dict:
#     # Get User attributes
#     payload = {'Table': 'users', 'ID': user_id}
#     logger.info(f'payload is:{payload}')
#     headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
#     logger.info(f'headers:{headers}')
#     url = f'{tenant_url}ExtData/GetColumns'
#     response = requests.request(method='POST', url=url, json=payload, headers=headers, timeout=30)
#     logger.info(f'Get user attributes response is:{response}')
#     if response.status_code == HTTPStatus.OK:
#         user_attributes = json.loads(response.text)['Result']
#         logger.info(user_attributes)
#         return user_attributes
#     return None

# def _get_identity_tanant_public_key(token: str, identity_public_key_url: str) -> jwk.Key:
#     logger.info(f'request to get token public key via: {identity_public_key_url}')
#     response = requests.get(url=identity_public_key_url, headers={'Authorization': f'Bearer {token}'},
#                             timeout=60)  # it is advised to cache the key results
#     logger.info(f'response status is: {response.status_code}')
#     if not response.text:
#         raise ValueError('identity response is empty')
#     logger.info(f'response text is: {response.text}')
#     response_dict = json.loads(response.text)
#     if not response_dict.get('keys', []):
#         raise ValueError('keys not found in response')
#     key = response_dict['keys'][0]
#
#     return jwk.construct(key)

# def verify_oidc_token_signature(tenant_url: str, token: str) -> bool:
#     """
#     Validate the oidc_token signature aagainst the CyberArk Identity public key.
#     TBD - Validate time
#
#     Parameters:
#         token (str): an OIDC token string which contains the user authentication
#
#     Returns:
#         result (bool): True if valid, otherwise raises an exception
#
#     Raises:
#         Value Error Exception
#         :param tenant_url:
#     """
#
#     key_url = f'{tenant_url}/OAuth2/Keys/__idaptive_cybr_user_oidc/'
#     public_key = _get_identity_tenant_public_key(token=token, identity_public_key_url=key_url)
#     message, encoded_sig = token.rsplit('.', maxsplit=1)
#     decoded_signature = base64url_decode(encoded_sig.encode('utf-8'))
#     if not public_key.verify(message.encode('utf8'), decoded_signature):
#         raise ValueError('Signature validation with public key failed')
#
#     return True

# @dataclass
# class Identifier:
#     entityId: str
#     entityType: str

# def _get_data_entities(token_claims: Dict, user_attributes: Dict = None) -> List:
#     data_entities: List[Dict] = []
#     # add roles from token
#     for role in token_claims['user_roles']:
#         data_entities.append({'identifier': asdict(Identifier(entityType='UserGroup', entityId=role))})
#
#     # add user and role parents
#     user_entity = {'identifier': asdict(Identifier(entityType='User', entityId=token_claims['sub'])), 'parents': []}
#     if user_attributes:
#         user_attributes_dict = {}
#         for attribute in user_attributes:
#             user_attributes_dict[attribute] = {'string': user_attributes[attribute]}
#         user_entity['attributes'] = user_attributes_dict
#
#     for role in token_claims['user_roles']:
#         user_entity['parents'].append(asdict(Identifier(entityType='UserGroup', entityId=role)))
#     data_entities.append(user_entity)
#     return data_entities

# def check_authorization(principal_id: str, action: str, resource: str, claims: Dict, user_attributes: Dict) -> str:
#     principal = Identifier(entityType='User', entityId=principal_id)
#     action = {'actionType': 'Action', 'actionId': action}
#     resource = Identifier(entityType='Resource', entityId=resource)
#     entities = {'entityList': _get_data_entities(token_claims=claims, user_attributes=user_attributes)}
#     context = {
#         'contextMap': {
#             'aws_region': {
#                 'string': claims['aws_region']
#             },
#             'last_login_time': {
#                 'long': int(claims['last_login'])
#             },
#             'login_time': {
#                 'long': int(datetime.now(timezone.utc).timestamp())
#             },
#             'weekday': {
#                 'long': datetime.now(timezone.utc).weekday()
#             },
#         }
#     }
#
#     logger.info(
#         f'store id:{POLICY_STORE_ID}, principal:{asdict(principal)}, action:{action}, resource:{asdict(resource)}, context:{context}, entities:{entities}'
#     )
#     authz_response = avp_client.is_authorized(
#         policyStoreId=POLICY_STORE_ID,
#         principal=asdict(principal),
#         resource=asdict(resource),
#         action=action,
#         context=context,
#         entities=entities,
#     )
#
#     return authz_response['decision']
