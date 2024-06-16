#!/bin/bash
set -e
STACK_NAME=avp-identity-source-stack
echo deploying a Policy store with schema and identity source for ID and Access Token

# try to delete if the stack exists, dont exit on error, wait for the stack to be deleted
aws cloudformation delete-stack --stack-name $STACK_NAME || true
aws cloudformation wait stack-delete-complete --stack-name $STACK_NAME || true

# create the stack
aws cloudformation deploy --template-file config/identity-source-cloudformation-template.yaml \
--stack-name $STACK_NAME --capabilities CAPABILITY_NAMED_IAM

# wait for the stack to be created
aws cloudformation wait stack-create-complete --stack-name $STACK_NAME

# Get Policy store id for ID Token
IdTokenPolicyStoreId=$(aws cloudformation describe-stacks --stack-name $STACK_NAME \
      --query "Stacks[0].Outputs[?OutputKey=='IdTokenPolicyStore'].OutputValue" --output text)

echo "IdTokenPolicyStoreId: $IdTokenPolicyStoreId"

AccessTokenPolicyStoreId=$(aws cloudformation describe-stacks --stack-name $STACK_NAME \
      --query "Stacks[0].Outputs[?OutputKey=='AccessTokenPolicyStore'].OutputValue" --output text)

echo "AccessTokenPolicyStoreId: $AccessTokenPolicyStoreId"

# set the identity-source-configuration for the ID Token
aws verifiedpermissions create-identity-source --configuration file://config/identity-source-config-id-token.json  \
    --principal-entity-type "NAMESPACE::User" --policy-store-id $IdTokenPolicyStoreId

# set the identity-source-configuration for the Access Token
aws verifiedpermissions create-identity-source --configuration file://config/identity-source-config-access-token.json  \
    --principal-entity-type "NAMESPACE::User" --policy-store-id $AccessTokenPolicyStoreId

