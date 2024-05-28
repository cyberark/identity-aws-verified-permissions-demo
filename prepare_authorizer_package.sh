#!/bin/bash
set -e
# validate args
if [ "$#" -ne 3 ]; then
    echo "Illegal number of parameters. Enter the following command and args:"
    echo "$0 <s3 bucket name> <cyberark identity url>" "<aws region>"
    exit 1
fi

# prepare package to deploy: copy function code and install packages
echo preparing the package

#mkdir -p package/models/verifiedpermissions/2021-12-01
rm -rf temp_dir
mkdir -p temp_dir
mkdir -p temp_dir/utils
touch temp_dir/__init__.py
cp ./lambda_function.py temp_dir
cp ./lambda_function_with_token.py temp_dir
cp ./utils/__init__.py temp_dir/utils/__init__.py
cp ./utils/utils.py temp_dir/utils/utils.py

echo installing python pre-requisites
# install using venv
#pip install -r requirements.txt.bak --target temp_dir
pip install -r requirements.txt  --no-deps --platform manylinux2014_x86_64 --target temp_dir

export BUCKET_NAME=$1
aws cloudformation package --template avp-authorizer-cf-template.yaml \
 --s3-bucket $BUCKET_NAME --output-template-file cf-package.yaml

echo deploying an API GW, Lambda Authorizer and sample API to region:$3
export IDENTITY_URL=$2
aws cloudformation deploy --template-file cf-package.yaml \
--stack-name avp-authorizer-stack --capabilities CAPABILITY_NAMED_IAM \
--parameter-overrides IdentityTenantUrl=$IDENTITY_URL \
--region $3