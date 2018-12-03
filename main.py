import json
import boto3
import gzip
import os

from config import tags_by_arn

s3 = boto3.client('s3')
sns = boto3.client('sns')

service_name_from_event_source = {
    's3.amazonaws.com': 's3',
    'ec2.amazonaws.com': 'ec2',
    'rds.amazonaws.com': 'rds',
}

target_events = {
    'ec2.amazonaws.com': {
        'RunInstances': {
            'extract_resource_ids': (lambda r: (i['instanceId'] for i in r['instancesSet']['items'])),
        },
        'CreateVolume': {
            'extract_resource_ids': (lambda r: [r['volumeId']]),
        },
        'CreateSnapshot': {
            'extract_resource_ids': (lambda r: [r['snapshotId']]),
        },
    },
}


def boto3_client(service, region_name):
    return boto3.client(service, region_name=region_name)

def get_cloudtrail_object(bucket, key):
    response = s3.get_object(
        Bucket=bucket,
        Key=key,
    )
    return json.loads(gzip.decompress(response['Body'].read()).decode())

def report_error(message):
    sns.publish(
        TopicArn=os.getenv('ERROR_SNS_TOPIC_ARN'),
        Message=message,
        Subject='aws-tags-by-cloudtrail error',
    )

def determine_tags(user_identity):
    t = user_identity['type']
    if t == 'Root':
        arn = user_identity['arn']
    elif t == 'IAMUser':
        arn = user_identity['arn']
    elif t == 'AssumedRole':
        arn = user_identity['sessionContext']['sessionIssuer']['arn']
    else:
        return {}
    return tags_by_arn.get(arn, {})
    
def handle_ct_record(record):
    response_elements = record['responseElements']
    event_source = record['eventSource']
    event_name = record['eventName']
    region = record['awsRegion']
    user_identity = record['userIdentity']

    h = target_events.get(event_source, {}).get(event_name)
    if h == None:
        return

    tags = determine_tags(user_identity)
    if len(tags) == 0:
        print("Reporting an error because no tags are found for {}".format(user_identity))
        report_error("Tags are not found for {}\n\nCloudTrail record: {}".format(user_identity, record))
        return
    
    boto_tags = []
    for k, v in tags.items():
        boto_tags.append({'Key': k, 'Value': v})

    resource_ids = list(h['extract_resource_ids'](response_elements))
    print("Tagging {} to {} in {}".format(tags, resource_ids, region))
    boto3_client(service_name_from_event_source[event_source], region).create_tags(
        Resources=resource_ids,
        Tags=boto_tags,
    )

def handle_object(bucket, key):
    print("Handling s3://{}/{}".format(bucket, key))
    ct = get_cloudtrail_object(bucket, key)
    print(ct)
    for record in ct['Records']:
        handle_ct_record(record)

def handler(event, context):
    print(json.dumps(event))
    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        for record in message['Records']:
            s3 = record['s3']
            bucket = s3['bucket']['name']
            key = s3['object']['key']
            handle_object(bucket, key)
