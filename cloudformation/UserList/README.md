ESP Report of Current Users
-----

The cloudformation stack generates the following resources:
- CloudWatch event to trigger Lambda report
- Lambda to generate report
- Destination S3 Bucket
- IAM roles with enough permissions to glue the stack together.

Step-by-step instructions:
1. Upload zip file to a public S3 Bucket for the lambda function to read for it's source code. This is defined in the Cloudformation parameters upon creation.
2. Launch the cloudformation stack using template-GetUsers.yaml
    - TargetS3Bucket: Report from Lambda function will go to this bucket. This should be a new S3 Bucket.
    - SourceCodeBucket: The S3 bucket from step #1

users_audit.py script is included in the zip file and by default pushes a csv report to an s3 bucket.

example Output

```
First Name,Last Name,Email,Role,Organization,Last Updated,MFA Enabled
....,.....,.....,.....

```


