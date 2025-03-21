import boto3
import json
import tabulate
from datetime import datetime
import logging
from pathlib import Path

class AWSAccountAuditor:
    def __init__(self):
        """Initialize the auditor using CloudShell's default credentials"""
        # CloudShell provides temporary credentials automatically
        self.session = boto3.Session()
        # Initialize service clients
        self.ec2_client = self.session.client('ec2')
        self.rds_client = self.session.client('rds')
        self.s3_client = self.session.client('s3')
        self.asg_client = self.session.client('autoscaling')
        self.elbv2_client = self.session.client('elbv2')
        self.backup_client = self.session.client('backup')
        self.cloudwatch_client = self.session.client('cloudwatch')
        # Configure logging
        logging.basicConfig(
            filename=f'aws_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def audit_ec2_instances(self):
    """Audit EC2 instances and their configurations"""
    try:
        response = self.ec2_client.describe_instances()
        instances_data = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                security_groups = [sg['GroupName'] for sg in instance.get('SecurityGroups', [])]
                
                # Handle IAM role with error checking
                iam_role = 'None'
                try:
                    if 'IamInstanceProfile' in instance:
                        iam_role = instance['IamInstanceProfile'].get('Arn', 'Not Available')
                    else:
                        iam_role = 'No IAM Role Attached'
                except Exception as e:
                    logging.error(f"Error fetching IAM role for instance {instance['InstanceId']}: {str(e)}")
                    iam_role = 'Error Fetching IAM Role'
                
                # Create a single dictionary for this instance
                instance_data = {
                    'Instance ID': instance['InstanceId'],
                    'Name': instance.get('Tags', [{}])[0].get('Name', 'N/A'),
                    'Type': instance['InstanceType'],
                    'State': instance['State']['Name'],
                    'Public IP': instance.get('PublicIpAddress', 'N/A'),
                    'Private IP': instance.get('PrivateIpAddress', 'N/A'),
                    'Security Groups': ','.join(security_groups),
                    'IAM Role': iam_role
                }
                
                # Get monitoring alarms
                metrics_response = self.cloudwatch_client.list_metrics(
                    Namespace='AWS/EC2',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance['InstanceId']}]
                )
                alarms = [metric['MetricName'] for metric in metrics_response['Metrics']]
                instance_data['Monitoring Alarms'] = ','.join(alarms) or 'None'
                
                instances_data.append(instance_data)
        
        # Print results with proper headers
        headers = ['Instance ID', 'Name', 'Type', 'State', 'Public IP',
                  'Private IP', 'Security Groups', 'IAM Role', 'Monitoring Alarms']
        print("\nEC2 Instances Audit Results:")
        print(tabulate.tabulate(instances_data, headers=headers, tablefmt='grid'))
        
    except Exception as e:
        logging.error(f"Error auditing EC2 instances: {str(e)}")
        print(f"Error: Unable to retrieve EC2 instances information")

def main():
    auditor = AWSAccountAuditor()
    while True:
        print("\n=== AWS Account Auditor ===")
        print("1. EC2 Instances")
        print("2. RDS Databases")
        print("3. S3 Buckets")
        print("4. Auto Scaling Groups")
        print("5. Load Balancers")
        print("6. Backup Configurations")
        print("7. CloudWatch Alarms")
        print("8. Exit")
        choice = input("\nEnter your choice (1-8): ")
        if choice == '1':
            auditor.audit_ec2_instances()
        elif choice == '2':
            print("RDS audit coming soon...")
        elif choice == '3':
            print("S3 audit coming soon...")
        elif choice == '4':
            print("ASG audit coming soon...")
        elif choice == '5':
            print("ELB audit coming soon...")
        elif choice == '6':
            print("Backup audit coming soon...")
        elif choice == '7':
            print("CloudWatch audit coming soon...")
        elif choice == '8':
            print("Thank you for using AWS Account Auditor!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == '__main__':
    main()
