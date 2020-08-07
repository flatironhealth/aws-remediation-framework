!/usr/bin/env bash
set -ex
bucket_name_prefix=$1
TERRAFORM_BUCKET=$bucket_name_prefix

mkdir -p cache
rm -f cache/*.zip

Field_Separator=$IFS
# set comma as internal field separator for the string list
IFS=,
for region in $regions;
do
echo $region
if [ $region = "us-east-1" ]; then
aws s3api create-bucket --bucket $TERRAFORM_BUCKET-$region
aws s3api put-bucket-tagging --bucket $TERRAFORM_BUCKET-$region --tagging 'TagSet=[{Key=App,Value=remediator}]'
else
aws s3api create-bucket --bucket $TERRAFORM_BUCKET-$region --region $region --create-bucket-configuration LocationConstraint=$region
aws s3api put-bucket-tagging --bucket $TERRAFORM_BUCKET-$region --tagging 'TagSet=[{Key=App,Value=remediator}]'
fi
done

# Install libraries
pip3 install --target resources/remediator/module_cache/ -r resources/remediator/requirements.txt
