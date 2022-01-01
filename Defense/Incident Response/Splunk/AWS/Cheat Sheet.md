<u>__Finding non-compliant s3 buckets without encryption and public:__</u>

(index=aws sourcetype=aws:config:rule ComplianceType=NON_COMPLIANT ("EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName"="s3-bucket-server-side-encryption-enabled" OR
"EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName"="s3-bucket-public-read-prohibited" OR "EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName"="s3-bucket-public-write-prohibited"))
| rename "EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId" AS Name
| rename "EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType" AS Type
| rename "EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName" AS Config_Rule
| fields + Name Type Config_Rule aws_account_id
| table Name Type Config_Rule aws_account_id
| dedup Name

<u>__One-off searches:__</u>

index=aws {{ bucket_name }} sourcetype="aws:cloudtrail" "resources{}.type"="AWS::S3::Object"

index=aws sourcetype="aws:cloudtrail" eventSource=s3.amazonaws.com (eventtype=aws_cloudtrail_* OR eventtype=AwsApiCall)

index=aws sourcetype=aws:cloudtrail eventSource=s3.amazonaws.com NOT requestParameters.publicAccessBlock="*" requestParameters.bucketName={{ bucket_name }}

index=aws sourcetype="aws:cloudtrail" eventSource=s3.amazonaws.com eventName=PutBucketPublicAccessBlock
| table _time eventName msg requestParameters.bucketName aws_account_id awsRegion userIdentity.arn

index=aws sourcetype=aws:cloudtrail AllUsers eventName=PutBucketAcl 
| spath output=userIdentityArn path=userIdentity.arn 
| spath output=bucketName path="requestParameters.bucketName" 
| spath output=aclControlList path="requestParameters.AccessControlPolicy.AccessControlList" 
| spath input=aclControlList output=grantee path=Grant{} 
| mvexpand grantee 
| spath input=grantee 
| search "Grantee.URI"=*AllUsers 
| table _time, Permission, Grantee.URI, bucketName, userIdentity.arn aws_account_id awsRegion
| sort - _time

<u>__Detect if s3 buckets have encryption enabled or not:__</u>

index=aws sourcetype="aws:cloudtrail" eventSource=s3.amazonaws.com eventName=PutBucketEncryption "requestParameters.ServerSideEncryptionConfiguration.Rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm"=AES256

<u>__AWS:S3 Bucket made public:__</u>

(index=aws sourcetype="aws:cloudtrail" eventSource=s3.amazonaws.com eventName=PutBucketPublicAccessBlock) OR
(index=aws sourcetype=aws:cloudtrail AllUsers eventName=PutBucketAcl)
| rename "requestParameters.bucketName" AS bucketName
| table _time bucketName userIdentity.arn aws_account_id awsRegion

<u>__S3 Non Compliant Audit:__</u>

(index=aws sourcetype=aws:config:rule ComplianceType=NON_COMPLIANT "EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName"="s3-bucket-server-side-encryption-enabled") OR
(index=aws sourcetype=aws:config:rule ComplianceType=NON_COMPLIANT "EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName"="s3-bucket-public-read-prohibited") OR
(index=aws sourcetype=aws:config:rule ComplianceType=NON_COMPLIANT "EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName"="s3-bucket-public-write-prohibited")
| rename "EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId" AS Name
| rename "EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType" AS Type
| rename "EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName" AS Config_Rule
| table Name Type Config_Rule aws_account_id

<u>__AWS: User Account Created:__</u>

index=aws eventSource="iam.amazonaws.com" eventName=CreateUser
| table _time eventName recipientAccountId requestParameters.userName userIdentity.arn

<u>__AWS: IAM Policy Change:__</u>

index=aws sourcetype="aws:cloudtrail" eventSource=iam.amazonaws.com (eventName=CreatePolicyVersion OR eventName=DeletePolicyVersion)
| table _time eventName recipientAccountId requestParameters.policyArn userIdentity.arn

<u>__AWS: Access Key Created:__</u>

index=aws sourcetype="aws:cloudtrail" eventSource=iam.amazonaws.com eventName=CreateAccessKey
| table _time eventName recipientAccountId requestParameters.userName userIdentity.arn
