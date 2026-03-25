# Cloud Security Monitoring Tool (AWS)

An end-to-end cloud security monitoring demo that combines:

Python-based security scanner
AWS SDK (Boto3) for resource inspection
IAM role-based secure authentication
CloudWatch Logs for audit and observability
SNS for real-time alerting
Linux cron for automated periodic scans

For the current demo:

EC2 scanning detects public exposure and insecure security groups
S3 scanning detects public access misconfigurations
alerts are sent via SNS email notifications
logs are stored in CloudWatch for audit and debugging
the system runs automatically using cron jobs

---

## Demo Architecture

ec2/: Linux EC2 instance running the monitoring script
scanner/: Python-based detection logic (EC2 + S3 checks)
aws/: IAM roles, SNS topics, CloudWatch logs
automation/: cron-based scheduling for periodic scans

---

## 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/cloud-security-monitor.git
cd cloud-security-monitor
```

---

## 2. Setup Environment

Ensure you are running on an EC2 instance with:

* IAM role attached (no access keys required)
* Python 3 installed
* boto3 installed

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 3. IAM Role Configuration

Attach an IAM role to EC2 with permissions:

* ec2:DescribeInstances
* ec2:DescribeSecurityGroups
* s3:ListAllMyBuckets
* s3:GetBucketPolicy
* s3:GetBucketAcl
* s3:GetBucketPublicAccessBlock
* sns:Publish
* logs:CreateLogGroup
* logs:CreateLogStream
* logs:PutLogEvents

---

## 4. Configure SNS Alerts

Create SNS topic:

* Name: cloud-security-alerts
* Add email subscription
* Confirm subscription

Update in code:

```python
topic_arn = "arn:aws:sns:REGION:ACCOUNT_ID:cloud-security-alerts"
```

---

## 5. Run the Scanner

```bash
python3 ec2_scanner.py
```

The script will:

* scan EC2 instances for public exposure
* analyze security groups for open ports
* scan S3 buckets for public access issues
* generate structured findings (JSON)
* send alerts via SNS
* log results to CloudWatch

---

## 6. Enable Automation (Cron)

Install cron:

```bash
sudo dnf install -y cronie
sudo systemctl start crond
sudo systemctl enable crond
```

Add cron job:

```bash
crontab -e
```

```bash
*/5 * * * * /usr/bin/python3 /home/ec2-user/ec2_scanner.py >> /home/ec2-user/scan.log 2>&1
```

---

## 7. Verify System

Check logs:

```bash
cat /home/ec2-user/scan.log
```

CloudWatch:

* Log group: cloud-security-logs
* Log stream: scan-results

SNS:

* Email alerts received on findings

---

## 8. Example Findings

```json
[
  {
    "resource_id": "i-xxxx",
    "issue": "Public EC2 with open port 22",
    "severity": "CRITICAL",
    "service": "EC2"
  },
  {
    "resource_id": "bucket-name",
    "issue": "S3 bucket does not block public access",
    "severity": "HIGH",
    "service": "S3"
  }
]
```

---

## 9. Full Demo Flow

Run the scanner manually or via cron.

The system will:

* fetch AWS resource configurations
* evaluate security rules
* detect misconfigurations
* generate structured findings
* send SNS alerts
* log results to CloudWatch

---

## 10. What is Real vs Heuristic

Real in the current demo:

EC2 security group analysis
public exposure detection
S3 public access checks
SNS alerting system
CloudWatch logging
cron-based automation

Heuristic in the current demo:

severity scoring logic
limited service coverage (EC2, S3 only)
single-region scanning

---

## 11. Current Best Demo Mode

For best demo experience:

* create one public S3 bucket (test case)
* ensure EC2 is secure (no open SSH)
* run scanner manually once
* then demonstrate cron automation
* show SNS email + CloudWatch logs

---

## 12. Technologies Used

AWS EC2, S3, IAM, SNS, CloudWatch
Python (boto3)
Linux (cron)

---

## 13. Future Enhancements

Auto-remediation of insecure configurations
multi-region scanning
dashboard for visualization
integration with SIEM tools
CIS benchmark compliance checks

---
