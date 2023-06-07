#!/bin/bash
set -e
# validate args
if [ "$#" -ne 4 ]; then
    echo "Illegal number of parameters. Enter the follwing command and args:"
    echo "$0 <s3 bucket name> <verified permissions policy store id> <cyberark identity url>" "<aws region>"
    exit 1
fi

# prepare package to deploy: copy function code and install packages
echo preparing the package

mkdir -p package
cp ./lambda_function.py package

echo installing python pre-requisites
pip install -q python-jose requests==2.29.0 --target package
# temporary copy last boto3 version that supports Amazon Verified Permissions
# this will be deleted when boto3 will support Amazon Verified Permissions

echo unzip packages
unzip -qq -o boto.zip -d package
export BUCKET_NAME=$1
aws cloudformation package --template avp-authorizer-cf-template.yaml \
 --s3-bucket $BUCKET_NAME --output-template-file cf-package.yaml

echo deploying an API GW, Lambda Authorizer and sample API to region:$4
export POLICY_STORE_ID=$2
export IDENTITY_URL=$3
aws cloudformation deploy --template-file cf-package.yaml \
--stack-name avp-authorizer-stack --capabilities CAPABILITY_NAMED_IAM \
--parameter-overrides policyStoreID=$POLICY_STORE_ID IdentityTenantUrl=$IDENTITY_URL \
--region $4