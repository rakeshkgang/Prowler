#!/bin/bash
#
# Prowler multi-account assessment script:
#   Used to drive the assessment of AWS accounts via Prowler, post-processing the output reports
#   and optimizing the effort involved via automation.
#
# Script version: 2.98
#
# Tunable parameters to review:
#   1) PARALLELISM: Can be tuned to specify how many accounts to assess simultaneously.
#       The instance size must be adjusted appropriately.
#       Be aware of AWS Account level EC2 API Throttling limits and to execute this script in an account with minimal workloads.
#       r6i.xlarge can sustain 12 parallel assessments based on memory testing.
#       Utilize appropriately sized EC2 instance (8=r6i.large,12=r6i.xlarge, 16=r6i.2xlarge)
#   2) AWSACCOUNT_LIST: Specify the accounts to be assessed using one of the supported methods:
#       The keyword "thisaccount" to specify only the account where this script is deployed
#   3) AWSACCOUNT_LIST_FILE: If using AWSACCOUNT_LIST="inputfile", specify the path to the file
#       If the file is located in the /use/local/prowler directory, specify the filename, else specify the full path
#       Account IDs can be specified on one line (space separated) or one Account ID per line
#   4) REGION_LIST: Specify regions (SPACE DELIMITED) if you wish to assess specific AWS regions
#       or leave allregions to include all regions.
#   5) IAM_CROSS_ACCOUNT_ROLE: The IAM Role name created for cross account access
#   6) ACCOUNTID_WITH_NAME: By default, the value is true, the value of ACCOUNT_NUM column in the final report is populated with Account Name
#       in the format <AccountId-AccountName>. Changing the value to false will produce the report with ACCOUNT_NUM=<AccountId>.
#   7) S3_BUCKET: The S3 bucket which will be used for Prowler report upload.
#       This is set by default to the S3 bucket provisioned during deployment.
#   8) CONSOLIDATED_REPORT: The name of the output report which does not have any grep filtering performed
#        Using .txt as 'CSV' output is semicolon delimited
#   9) CONSOLIDATED_REPORT_FILTERED: The name of the output report which does have grep filtering performed to remove common errors.
#        Using .txt as 'CSV' output is semicolon delimited
#       This file is recommended to be used for reporting as know errors are removed and provide cleaner output
#   10) The prowler command within the for loop can also be tuned to meet the needs of the assessment.
#       prowler -R arn:aws-partition:iam::$ACCOUNTID:role/$IAM_CROSS_ACCOUNT_ROLE -M csv json-ocsf html -T 43200 --verbose | tee output/stdout-$ACCOUNTID.txt 1>/dev/null
#       See Prowler documentation for all options.
#   11) FINDING_OUTPUT: To reduce the amount of output and focus on FAIL findings vs both FAIL and PASS, --status FAIL is specified.
#       If both FAIL and PASS findings output is desired, comment out the entire variable or set FINDING_OUTPUT=
#
#########################################

# Variables which can be modified: (In most cases, scanning all accounts and all regions is preferred for a complete assessment)

# Adjust PARALLELISM to adjust the number of parallel scans
PARALLELISM="16"

# Specify accounts to be assessed using one of the supported methods:

AWSACCOUNT_LIST="924144197303 851725370590" 
# Specify the regions to have assessed (space separated) or use the keyword allregions to include all regions:
REGION_LIST="allregions"
# REGION_LIST="us-east-1 us-east-2"

# Specify an IAM Role to use for cross account access in the target accounts (Execution Role):
IAM_CROSS_ACCOUNT_ROLE="ProwlerExecRole"

# Specify whether to output Account ID with Account Name in the final report. (set to false to disable)
ACCOUNTID_WITH_NAME=true

# S3 bucket where report will be uploaded
S3_BUCKET="test-2025-924144197303"

# Consolidated output report without error filtering (Using .txt as 'CSV' output is semicolon delimited)
CONSOLIDATED_REPORT=output/prowler-fullorgresults.txt

# Consolidated output report with error filtering (Using .txt as 'CSV' output is semicolon delimited) (Recommended to be used for reporting)
CONSOLIDATED_REPORT_FILTERED=output/prowler-fullorgresults-accessdeniedfiltered.txt

# Comment out this variable (or set FINDING_OUTPUT=) to have Prowler output both PASS *and* FAIL findings.  With --status FAIL, *ONLY* FAIL will be output
FINDING_OUTPUT='--status FAIL'

#########################################

# Clean up Last Ran Prowler Reports if they exist
rm -rf output/*

# Create output folder for first time scan with redirected stout
mkdir -p output

# Unset environment variables if they exist and utilize IAM Role attached to the EC2 instance
unset_aws_environment() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}
unset_aws_environment

# Determine the executing account AWS Number and Partition
CALLER_IDENTITY_ARN=$(aws sts get-caller-identity --output text --query "Arn")
AWSPARTITION=$(echo "$CALLER_IDENTITY_ARN" | cut -d: -f2)
EXECACCOUNT=$(echo "$CALLER_IDENTITY_ARN" | cut -d: -f5)
echo ""
echo "AWS account Prowler is executing from: $EXECACCOUNT"
echo ""

# Assume Role in Management account and export session credentials
management_account_session() {
    AWSMANAGEMENT=$(aws organizations describe-organization --query Organization.MasterAccountId --output text)
    echo "AWS organization Management account: $AWSMANAGEMENT"

    unset_aws_environment
    ROLE_SESSION_CREDS=$(aws sts assume-role --role-arn arn:"$AWSPARTITION":iam::"$AWSMANAGEMENT":role/"$IAM_CROSS_ACCOUNT_ROLE" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "$ROLE_SESSION_CREDS" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$ROLE_SESSION_CREDS" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$ROLE_SESSION_CREDS" | jq -r .Credentials.SessionToken)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Monitor the number of background processes and return to task execution for loop when bg jobs are less than PARALLELISM limit
process_monitor() {
    while [ "$(jobs | grep Running | wc -l)" -ge $PARALLELISM ]
    do
        echo "Sleeping 20 seconds while waiting for active assessment queue to clear..."
        sleep 5
    done
}

# Display account and region selection
echo ""
echo "AWS Accounts being processed: Specified AWS accounts: $AWSACCOUNT_LIST"
echo ""
echo "AWS regions being processed:"
if [ "$REGION_LIST" == "allregions" ]; then
    echo "All AWS regions"
else
    echo $REGION_LIST
fi

echo ""
echo "Prowler Finding Output Mode:"
if [ "$FINDING_OUTPUT" == "--status FAIL" ]; then
    echo "Failed Findings Only"
else
    echo "Failed and Passed Findings"
fi

echo ""
echo "Output from prowler assessments will be redirected to output/stdout-<accountId>.txt and errors will be shown on the console"
echo "tail -f these files to monitor progress of individual account assessments"
echo ""

# Run Prowler against the selected account and regions
if [ "$REGION_LIST" == "allregions" ]; then
    for ACCOUNTID in $AWSACCOUNT_LIST; do
        test "$(jobs | grep Running | wc -l)" -ge $PARALLELISM && process_monitor || true
        {
            # Unset AWS Profile Variables
            unset_aws_environment
            echo -e "Assessing AWS Account: $ACCOUNTID with all AWS regions using Role: $IAM_CROSS_ACCOUNT_ROLE on $(date)"
            # Run Prowler
            /usr/local/bin/prowler -R arn:$AWSPARTITION:iam::$ACCOUNTID:role/$IAM_CROSS_ACCOUNT_ROLE -M csv json-ocsf html ${FINDING_OUTPUT:-} -T 1200 --verbose | tee output/stdout-$ACCOUNTID.txt 1>/dev/null
        } &
    done
fi

# Wait for All Prowler Processes to finish
wait
echo ""
echo "Prowler assessments have been completed against the selected account"
echo ""

# Unset the STS AssumeRole session and revert to permissions via the EC2 attached IAM Role
unset_aws_environment

# Prowler Output Post-Processing
echo "======================================================================================"
echo "Prowler Output Post-Processing"
echo "======================================================================================"
echo ""

# Function to upload reports to S3
upload_to_s3() {
    echo "Uploading Prowler reports to S3 bucket: $S3_BUCKET"
    aws s3 cp output/ "s3://$S3_BUCKET/" --recursive
}

# Call the function to upload reports to S3
upload_to_s3