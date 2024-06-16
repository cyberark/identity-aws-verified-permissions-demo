import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Dict, List

import boto3
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode
from requests_oauth2client import OAuth2Client
from retry import retry

logger = logging.getLogger()
logger.setLevel(logging.INFO)


@dataclass
class Identifier:
    entityId: str
    entityType: str

@retry(tries=3, delay=2)
def identity_login(identity_url: str, username: str, password: str) -> str:
    try:
        print('identity url:', identity_url)
        oauth2client = OAuth2Client(
            token_endpoint=f'{identity_url}/oauth2/platformtoken',
            auth=(username, password),
            timeout=10)
        token = oauth2client.client_credentials(scope="", resource="")
        return str(token)
    except (Exception) as ex:
        print(ex.error)
        if "access_denied" in ex.error:
            raise Exception("Access Denied")


def _get_data_entities(token_claims: Dict,
                       user_attributes: Dict = None) -> List:
    """ Get data entities from token claims and user attributes

    Parameters:
        token_claims:
        user_attributes:

    Returns:
        List: The data entities list
    """
    if not token_claims:
        return None

    # add roles from token
    groups = token_claims.get('user_roles') or token_claims.get('roles') or token_claims.get('groups')

    data_entities: List[Dict] = []
    for role in groups:
        data_entities.append({
            'identifier':
            asdict(Identifier(entityType='UserGroup', entityId=role))
        })

    # add user and role parents
    user_entity = {
        'identifier':
        asdict(Identifier(entityType='User', entityId=token_claims['sub'])),
    }
    if user_attributes:
        user_entity['attributes'] = {attribute: {'string': user_attributes[attribute]} for attribute in user_attributes}

    if groups:
        user_entity['parents'] =  [asdict(Identifier(entityType='UserGroup', entityId=role)) for role in groups]

    data_entities.append(user_entity)

    return data_entities


@retry(tries=3, delay=2)
def get_identity_user_attributes(tenant_url: str, token: str,
                                 user_id: str) -> Dict:
    """ Get user attributes from the CyberArk Identity service
    Parameters:
        tenant_url: str: The tenant url
        token: str: The token
        user_id: str: The user id
    Returns:
        Dict: The user attributes dictionary
    """

    # Get User attributes
    payload = {'Table': 'users', 'ID': user_id}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    if tenant_url.endswith("/"):
        url = f'{tenant_url}ExtData/GetColumns'
    else:
        url = f'{tenant_url}/ExtData/GetColumns'

    response = requests.request(method='POST',
                                url=url,
                                json=payload,
                                headers=headers,
                                timeout=30)
    if response.status_code == HTTPStatus.OK:
        user_attributes = json.loads(response.text)['Result']
        return user_attributes
    return None


def _get_avp_client(region: str = 'us-east-1'):
    """ Get a client for the verifiedpermissions service
    Parameters:
        region: str: The AWS region
    Returns:
        boto3.client: The client for the verifiedpermissions service
    """
    client = boto3.client('verifiedpermissions', region_name=region)
    return client


def _get_avp_common_kwargs(policy_store_id: str,
                           action: str,
                           resource_id: str = "",
                           user_attributes: Dict = None,
                           claims: Dict = None) -> Dict:
    """ Get common kwargs for the AVP check_authorization method """
    kwargs = {
        'policyStoreId': policy_store_id,
        'action': {
            'actionType': 'NAMESPACE::Action',
            'actionId': action
        },
    }

    if resource_id and len(resource_id) > 0:
        kwargs['resource'] = asdict(
            Identifier(entityType='Resource', entityId=resource_id))

    if user_attributes and len(user_attributes) > 0 or claims:
        entities = {
            'entityList':
            _get_data_entities(token_claims=claims,
                               user_attributes=user_attributes)
        }
        kwargs['entities'] = entities

    logger.info(f"AVP kwargs: {kwargs}")

    return kwargs


def check_authorization(policy_store_id: str,
                        principal_id: str,
                        action: str,
                        resource_id: str = "",
                        token: str = "") -> str:

    """ Check authorization using the AVP service
    Parameters:
        policy_store_id: str: The policy store id
        principal_id: str: The principal id
        action: str: The action to check
        region: str: The AWS region
        resource_id: str: The resource id
        token: str: The token
    Returns:
        str: The result of the authorization check
    """

    claims = jwt.get_unverified_claims(token)
    default_app = "__idaptive_cybr_user_oidc/"
    tenant_url = claims['iss'].replace(default_app, '')
    user_id = claims['sub']
    logger.info(f'principal: {user_id}')

    user_attributes = _get_user_attributes(tenant_url=tenant_url,
                                           token=token,
                                           user_id=user_id)
    logger.info(f'user attributes:{user_attributes}')

    logger.info(f"""authorization request args\n
                    Policy:{policy_store_id}\n
                    principal id: {principal_id}\n
                    method: {action}\n
                    resource_id:{resource_id}\n
                    token: {token}\n
                    user_attributes: {user_attributes}\n
                    """)

    kwargs = _get_avp_common_kwargs(policy_store_id=policy_store_id,
                                    action=action,
                                    resource_id=resource_id,
                                    user_attributes=user_attributes,
                                    claims=claims)
    if principal_id:
        kwargs['principal'] = asdict(
            Identifier(entityType='User', entityId=principal_id))

    # add entities and context
    region = boto3.session.Session().region_name
    authz_response = _get_avp_client(region=region).is_authorized(**kwargs)

    return authz_response['decision']


def _get_context_map(claims: Dict) -> Dict:
    """  Extracts the context map from the claims """

    context_map = {}

    # taking metadata from the token (CyberArk Identity token)
    if 'aws_region' in claims:
        context_map['aws_region'] = {'string': claims['aws_region']}

    if 'last_login' in claims:
        context_map['last_login_time'] = {'long': int(claims['last_login'])}

    # Context variables from the current time

    now = datetime.now(timezone.utc)
    context_map['login_time'] = {'long': int(now.timestamp())}

    context_map['weekday'] = {'long': now.weekday()}

    return {'contextMap': context_map} if context_map else None


def check_authorization_with_token(policy_store_id: str,
                                   region: str,
                                   id_token: str = None,
                                   access_token: str = None,
                                   action: str = None,
                                   resource_id: str = None,
                                   user_attributes: Dict = None) -> str:

    """ Check authorization for a given principal, action, resource and user attributes
    Parameters:
        policy_store_id: str
            The policy store id
        region: str
            The region where the verified permissions service is deployed
        id_token: str
            The id token
        access_token: str
            The access token
        action: str
            The action to be performed
        resource_id: str
            The resource id
        user_attributes: Dict
            The user attributes
    Returns:
        str
            The authorization decision
    """

    claims = jwt.get_unverified_claims(id_token or access_token)
    kwargs = _get_avp_common_kwargs(policy_store_id=policy_store_id,
                                    action=action,
                                    resource_id=resource_id,
                                    user_attributes=user_attributes,
                                    claims=claims)
    if id_token:
        kwargs['identityToken'] = id_token

    elif access_token:
        kwargs['accessToken'] = access_token

    if claims and len(claims) > 0:
        kwargs['context'] = _get_context_map(claims)

    authz_response = _get_avp_client(region=region).is_authorized_with_token(
        **kwargs)

    return authz_response['decision']


def _get_user_attributes(tenant_url: str, token: str, user_id: str) -> Dict:
    """ Get user attributes from the tenant
    Parameters:
        tenant_url: str
            The tenant url
        token: str
            The token
        user_id: str
            The user id
    Returns:
        Dict
            The user attributes
    """

    # Get User attributes
    payload = {'Table': 'users', 'ID': user_id}
    logger.info(f'payload is:{payload}')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    logger.info(f'headers:{headers}')
    url = ""
    if tenant_url.endswith("/"):
        url = f'{tenant_url}ExtData/GetColumns'
    else:
        url = f'{tenant_url}/ExtData/GetColumns'

    logger.info(
        f'before requesting user attributes from :{url}, with payload:{payload} and headers:{headers}'
    )

    response = requests.request(method='POST',
                                url=url,
                                json=payload,
                                headers=headers,
                                timeout=30)
    logger.info(f'Get user attributes response is:{response}')
    if response.status_code == HTTPStatus.OK:
        user_attributes = json.loads(response.text)['Result']
        logger.info(user_attributes)
        return user_attributes

    return None


def _get_identity_tenant_public_key(token: str,
                                    identity_public_key_url: str) -> jwk.Key:
    """ Get the public key from the CyberArk Identity tenant
    Parameters:
        token: str
            The token
        identity_public_key_url: str
            The identity public key url
    Returns:
        jwk.Key
            The public key
    """
    logger.info(
        f'request to get token public key via: {identity_public_key_url}')
    response = requests.get(
        url=identity_public_key_url,
        headers={'Authorization': f'Bearer {token}'},
        timeout=60)  # it is advised to cache the key results
    logger.info(f'response status is: {response.status_code}')
    if not response.text:
        raise ValueError('identity response is empty')
    logger.info(f'response text is: {response.text}')
    response_dict = json.loads(response.text)

    if not response_dict.get('keys'):
        raise ValueError('keys not found in response')
    key = response_dict['keys'][0]

    return jwk.construct(key)


def verify_oidc_token_signature(tenant_url: str, token: str) -> bool:
    """
    Validate the oidc_token signature against the CyberArk Identity public key.
    TBD - Validate time

    Parameters:
        token (str): an OIDC token string which contains the user authentication

    Returns:
        result (bool): True if valid, otherwise raises an exception

    Raises:
        Value Error Exception
        :param tenant_url:
    """

    key_url = f'{tenant_url}/OAuth2/Keys/__idaptive_cybr_user_oidc/'
    public_key = _get_identity_tenant_public_key(
        token=token, identity_public_key_url=key_url)
    message, encoded_sig = token.rsplit('.', maxsplit=1)
    decoded_signature = base64url_decode(encoded_sig.encode('utf-8'))
    if not public_key.verify(message.encode('utf8'), decoded_signature):
        raise ValueError('Signature validation with public key failed')

    return True
