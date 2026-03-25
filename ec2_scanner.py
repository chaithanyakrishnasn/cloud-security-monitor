import boto3
import json
import time

# -------------------------------
# EC2 SECURITY CHECKS
# -------------------------------


def check_security_groups(ec2_client, security_group_ids):
    risky_ports = [22, 3389]
    is_open = False
    issues = []

    response = ec2_client.describe_security_groups(GroupIds=security_group_ids)

    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']

        for permission in sg.get('IpPermissions', []):
            from_port = permission.get('FromPort')

            for ip_range in permission.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')

                if cidr == "0.0.0.0/0":
                    is_open = True
                    issues.append({
                        "sg_id": sg_id,
                        "port": from_port
                    })

    return is_open, issues


def fetch_ec2_instances():
    region = "ap-south-1"
    ec2 = boto3.client('ec2', region_name=region)

    findings = []

    response = ec2.describe_instances()

    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            public_ip = instance.get('PublicIpAddress')

            sg_ids = [sg['GroupId'] for sg in instance['SecurityGroups']]

            is_open, issues = check_security_groups(ec2, sg_ids)

            # CRITICAL: Public + Open SG
            if public_ip and is_open:
                for issue in issues:
                    findings.append({
                        "resource_id": instance_id,
                        "issue": f"Public EC2 with open port {issue['port']} to 0.0.0.0/0",
                        "severity": "CRITICAL",
                        "service": "EC2",
                        "region": region
                    })

    return findings


def send_to_cloudwatch(findings):
    logs = boto3.client('logs', region_name='ap-south-1')

    log_group = "cloud-security-logs"
    log_stream = "scan-results"

    # Create log group (if not exists)
    try:
        logs.create_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    # Create log stream (if not exists)
    try:
        logs.create_log_stream(
            logGroupName=log_group,
            logStreamName=log_stream
        )
    except logs.exceptions.ResourceAlreadyExistsException:
        pass

    # Prepare log event
    timestamp = int(time.time() * 1000)

    message = json.dumps(findings)

    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[
            {
                'timestamp': timestamp,
                'message': message
            }
        ]
    )

# -------------------------------
# S3 DISCOVERY
# -------------------------------


def list_s3_buckets():
    s3 = boto3.client('s3')

    response = s3.list_buckets()

    buckets = []

    for bucket in response['Buckets']:
        bucket_name = bucket['Name']
        print(f"S3 Bucket Found: {bucket_name}")
        buckets.append(bucket_name)

    return buckets


def check_s3_public_access():
    s3 = boto3.client('s3')

    findings = []

    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']

        # Check Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            block_config = pab['PublicAccessBlockConfiguration']

            if not all(block_config.values()):
                findings.append({
                    "resource_id": bucket_name,
                    "issue": "S3 bucket does not block public access",
                    "severity": "HIGH",
                    "service": "S3",
                    "region": "global"
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "resource_id": bucket_name,
                "issue": "No public access block configuration found",
                "severity": "HIGH",
                "service": "S3",
                "region": "global"
            })

        # Check ACL
        acl = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})

            if grantee.get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                findings.append({
                    "resource_id": bucket_name,
                    "issue": "S3 bucket is publicly accessible via ACL",
                    "severity": "CRITICAL",
                    "service": "S3",
                    "region": "global"
                })

    return findings


def send_sns_alert(findings):
    sns = boto3.client('sns', region_name='ap-south-1')

    topic_arn = "your-arn-here"  # Replace with your SNS topic ARN

    message = json.dumps(findings, indent=2)

    sns.publish(
        TopicArn=topic_arn,
        Subject="🚨 Cloud Security Alert",
        Message=message
    )


# -------------------------------
# MAIN EXECUTION
# -------------------------------

if __name__ == "__main__":
    print("🔍 Starting Cloud Security Scan...\n")

    # EC2 Scan
    ec2_findings = fetch_ec2_instances()

    # S3 Scan (discovery only for now)
    s3_findings = check_s3_public_access()

    print("\n=== EC2 Findings ===")
    print(json.dumps(ec2_findings, indent=4))

    print("\n=== S3 Findings ===")
    print(json.dumps(s3_findings, indent=4))

    all_findings = ec2_findings + s3_findings

    # Send to CloudWatch
    send_to_cloudwatch(all_findings)

    if all_findings:
        print("\n🚨 Sending SNS Alert...")
        send_sns_alert(all_findings)
    else:
        print("\n✅ No security issues found")
