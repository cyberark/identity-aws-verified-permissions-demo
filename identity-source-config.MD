# Examples to configure Amazon Verified Permissions with CybnerArk Identity
This directory contains examples of configuration files for Amazon Verified Permissions with CybnerArk Identity.
The examples directory contains the following files:
* redirect_server.py - this script opens is a web server in local machine port 5000.
This application should be registered in CybberArk Identity. 
* token_login.py - this script is used to get the token from the redirect server and launch an authorization call to 
Amazon Verified Permissions. The example logins to CyberArk Identity using a client ID and client secret.
The result is an ID Token and Access tokem that is used to call Amazon Verified Permissions.
The call to Amazon Verified Permissions is done using the is_authorizied_with_token function. 
The result s a JSON object with the permissions.

#Identity-cusomization directory
This directoruy contains examples of login script in Javascript
This script can set the content of claims in the ID or Access token.
it uses the following functions to set the claims in the token:
* **setClaims** - to set the claim, eather a string, boolean or number 
* **setObject** - to set an object containing fields or sub-objects in the claim
* **setArray** - to set an array of values in the claim. e.g. the roles

# Configuration for the policy store with an Identity Source
This directory contains examples of configuration files for the policy store.

## Setup the schema of a policy store
Here is the command to setup the schema of a policy store:

``` bash
aws verifiedpermissions put-schema --policy-store-id <policy-store-id> \ 
--definition file://policy-store-configuration/id-token-schema.json
```

here are policy store schema files fpr an ID token and an access token: 
* **id-token-schema.json** - a schema file mapping between the ID token claims and the user attributes
* **access-token-schema.json** - a schema file mapping between the access token claims and the user attributes



## Setup a policy store identity source 
Here is the command to set the policy store identity source. 
The configuration file content defines if it's an ID or an Access token

``` bash 
aws verifiedpermissions create-identity-source \ 
--configuration file://identity-source-config-id-token.json --principal-entity-type \"User\" \ 
--policy-store-id 123456789012.
```
Here are the example configuration files for and ID token and access token as identity sources for the policy store: 
* identity-source-config-id-token.json - configuration file for the ID token as an identity source for the policy store
* identity-source-config-access-token.json - configuration file for the access token as an identity source for the policy store

## Example Cedar policies for ID and Access Tokens
* **id-token-policy** - a policy file that defines the policies in the policy store. It is written in Cedar Policy Language (CPL)
* **access-token-policy** - a policy file that defines the policies in the policy store. It is written in Cedar Policy Language (CPL)
