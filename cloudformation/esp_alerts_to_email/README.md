## ESP Alerts Export to email
-----

### HOW IT WORKS

Evident :arrow_right: SNS (integration) :arrow_right: Lambda :arrow_right: SNS (Email) :arrow_right: Email notification

### HOW TO USE:
First, launch the Stack:
1. Login to [Cloudformation Console](https://console.aws.amazon.com/cloudformation/)
2. Select the region, and select **Create Stack**
3. Choose `Upload a template to Amazon S3` and use the [cloudformation.json](./cloudformation.json)
4. Follow Select `Next` until you launch the stack.
5. Take a note of the `OUTPUT` tab once the cloudformation launch is completed.

Configure Evident SNS Integration:
1. Go to https://esp.evident.io/control_panel/integrations and create SNS integration
2. Specify the name, and use the following information from the cloudformation `output` section:
    - `SNSTopicArn`
    - `ExternalId`
    - `EvidentRoleArn`
3. Choose the external accounts, alert types (we recommend to choose FAIL only)
4. Select the signature that you want to be notified by email.
5. Select Save. You will be redirected back to the integration page
6. Find the newly created SNS integration, click `Test and Activate`

### PARAMETERS:

The cloudformation template requires the following parameters:
- `required` **TargetEmail** : This is the target email address to be subscribed to the SNS topic
- **EmailSNSTopicName** : This is SNS topic name which will send the formatted email alert
- **SNSIntegrationTopicName** : This is the SNS topic in which Evident sends the raw alert to. This SNS topic will trigger lambda
- **EspEvidentAccountId** : This is the ESP account ID which will push the SNS message. You can leave it as it is.

### RESOURCES CREATED:
- SNS Topic (for Evident to send the alert to) + Evident IAM role which has access to push to this topic
- SNS Topic (for Lambda's formatted email message) + Lambda IAM role which has access to push to this topic
- Lambda function which converts the raw alert message and push the formatted message to the 'email' SNS topic.