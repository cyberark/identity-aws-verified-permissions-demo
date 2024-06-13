# Authentication and Authorization

## Run the redirect server
run the authorization code server. a login will redirect to this server and provide an authorization code.

```bash
python ./redirect_server.py
```  

to verify the server is functioning you can use a browser to check availability or a command line
```bash  
curl http://localhost:8080
```

## Run the login script 

```bash
python ./token_login_authorize.py -i <idenity-url> -a <identity-oidc-app> -c <client-id> -psi <policy-store-id-id-token> -psa <policy-store-id-access-token> -region <region>
```
```
* idenity-url - for example https://abc1234.my.dev.idaptive.app
* identity-oidc-app - for example AVPDemo
* client-id - for example 12345678-1234-1234-1234-123456789012
* policy-store-id-id-token - for example 12345678-1234-1234-1234-123456789012
* policy-store-id-access-token - for example 12345678-1234-1234-1234-123456789012
* region - for example us-east-2
```

## Get the authorization code
1. The login will open a browser and authenticate with the user and password provided.
2. CyberArk Identity will redirect (after successful login) to the redirect server.
3. The redirect server will display the authorization code you received from CyberArk Identity
4. Copy the authorization code and paste it into the token script.
5. The token script will exchange the authorization code for an access token or id token.

## Authorize with Amazon Verified Permissions

1. The script will get the ID and Access token from CyberArk Identity
2. It presents the claims in the token.
```
{'Department': 'Customer',
 'app_id': 'AVPCyberArk',
 'aud': '7299a5ff-b2da-4f47-83c2-46d531809f48',
 'auth_time': 1718276694,
 'exp': 1718300144,
 'family_name': 'Name',
 'given_name': 'Fa',
 'groups': ['LastPass_Role',
            'System Administrator',
            'Wiz Settings Admin',
            'Customer',
            'Everybody',
            'Zscaler Role'],
 'iat': 1718282144,
 'iss': 'https://<tenant-id>.my.dev.idaptive.app/AVPCyberArk/',
 'name': 'Name Family',
 'project_list': ['Alpha', 'Lion', 'Eagle', 'Bob'],
 'roles': ['LastPass_Role',
           'System Administrator',
           'Wiz Settings Admin',
           'Customer',
           'Everybody',
           'Zscaler Role'],
 'scope': 'openid profile',
 'session_boolean': True,
 'session_config_json': {'session_idle': 30, 'timeout': 120},
 'session_time_long': 92233720368547760,
 'sub': '54fef19d-924a-4b73-a01d-8108bf8652d8',
 'unique_name': 'name.family@waseem.test'}
```
3. It invokes the authorization of Amazon Verified Permissions to the specific Policy Store
4. Amazon will returns an allow or deny permission according to the policies. 
The script will display the result of the authorization for ID token and Access token
```commandline
Authorizing with ID Token...
Authorization decision: ALLOW
Authorizing with Access Token...
Authorization decision: ALLOW
```
```
