!/usr/bin/env bash
set -ex
bucket_name_prefix=$1
TERRAFORM_BUCKET=$bucket_name_prefix

mkdir -p cache
rm -f cache/*.zip

# Create a .zip of src for the remediator
pushd resources/remediator
zip -r --exclude=module_cache/* ../../cache/remediator.zip *
pushd module_cache
zip -r ../../../cache/remediator.zip -u *
popd
popd
# Create a .zip of src for the poller
pushd resources/poller
zip -r --exclude=module_cache/* ../../cache/poller.zip *
popd
# Create a .zip of src for the event_translator
pushd resources/event_translator
zip -r --exclude=module_cache/* ../../cache/event_translator.zip *
popd

#iterate over regions
Field_Separator=$IFS
# set comma as internal field separator for the string list
IFS=,
for region in $regions;
do
if [ $region = $master_region ]; then
#poller and remediator will be deployed in main_region
aws s3 cp cache/remediator.zip s3://$TERRAFORM_BUCKET-$region/remediator.zip --sse
aws s3 cp cache/poller.zip s3://$TERRAFORM_BUCKET-$region/poller.zip --sse
aws s3 cp cache/event_translator.zip s3://$TERRAFORM_BUCKET-$region/event_translator.zip --sse
else
# This lambda needs to be moved to all regions
aws s3 cp cache/event_translator.zip s3://$TERRAFORM_BUCKET-$region/event_translator.zip --sse

fi
done

# Deploy the AWS resources

terraform apply -var lambda_bucket=$TERRAFORM_BUCKET
