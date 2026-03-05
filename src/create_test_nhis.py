"""
Erstellt Test-NHIs für die Entwicklung des Discovery Tools
ACHTUNG: Nur für Test-Accounts verwenden!
"""

import boto3
import json

def create_test_nhis():
    """Erstellt verschiedene Test-NHIs mit typischen Problemen"""
    
    iam = boto3.client('iam')
    
    print("🔧 Creating test NHIs...\n")
    
    # =========================================================
    # 1. Alter ungenutzter Service Account mit Admin-Rechten
    # =========================================================
    try:
        print("Creating: svc-old-backup (simulated old unused admin)")
        iam.create_user(UserName='svc-old-backup')
        iam.attach_user_policy(
            UserName='svc-old-backup',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        # Access Key erstellen (wird nie benutzt werden = Problem!)
        key1 = iam.create_access_key(UserName='svc-old-backup')
        print(f"   ✅ Created with Admin rights")
        print(f"   ⚠️  Access Key: {key1['AccessKey']['AccessKeyId']} (simulating unrotated key)")
    except iam.exceptions.EntityAlreadyExistsException:
        print("   ⏭️  Already exists, skipping")
    
    # =========================================================
    # 2. Deployment Service Account (typischer CI/CD Account)
    # =========================================================
    try:
        print("\nCreating: svc-deployment (CI/CD service account)")
        iam.create_user(UserName='svc-deployment')
        
        # Etwas eingeschränktere Rechte, aber immer noch zu viel
        iam.attach_user_policy(
            UserName='svc-deployment',
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess'
        )
        iam.attach_user_policy(
            UserName='svc-deployment',
            PolicyArn='arn:aws:iam::aws:policy/AmazonEC2FullAccess'
        )
        key2 = iam.create_access_key(UserName='svc-deployment')
        print(f"   ✅ Created with S3 + EC2 Full Access")
        print(f"   🔑 Access Key: {key2['AccessKey']['AccessKeyId']}")
    except iam.exceptions.EntityAlreadyExistsException:
        print("   ⏭️  Already exists, skipping")
    
    # =========================================================
    # 3. Externer API Service Account (z.B. für Partner-Integration)
    # =========================================================
    try:
        print("\nCreating: svc-external-api (external integration)")
        iam.create_user(UserName='svc-external-api')
        iam.attach_user_policy(
            UserName='svc-external-api',
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
        )
        key3 = iam.create_access_key(UserName='svc-external-api')
        print(f"   ✅ Created with S3 Read Only (good practice!)")
        print(f"   🔑 Access Key: {key3['AccessKey']['AccessKeyId']}")
    except iam.exceptions.EntityAlreadyExistsException:
        print("   ⏭️  Already exists, skipping")
    
    # =========================================================
    # 4. Lambda Execution Role (zu viele Rechte)
    # =========================================================
    try:
        print("\nCreating: role-lambda-overprivileged (overprivileged role)")
        
        # Trust Policy: Lambda darf diese Role annehmen
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam.create_role(
            RoleName='role-lambda-overprivileged',
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Lambda role with too many permissions (for testing)'
        )
        # Problem: Full Admin Access für eine Lambda!
        iam.attach_role_policy(
            RoleName='role-lambda-overprivileged',
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        print(f"   ✅ Created with AdministratorAccess")
        print(f"   ⚠️  This is a security risk!")
    except iam.exceptions.EntityAlreadyExistsException:
        print("   ⏭️  Already exists, skipping")
    
    # =========================================================
    # 5. EC2 Instance Role (moderat)
    # =========================================================
    try:
        print("\nCreating: role-ec2-webserver (typical EC2 role)")
        
        trust_policy_ec2 = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam.create_role(
            RoleName='role-ec2-webserver',
            AssumeRolePolicyDocument=json.dumps(trust_policy_ec2),
            Description='EC2 role for web servers'
        )
        # Moderate Rechte - S3 lesen + CloudWatch Logs
        iam.attach_role_policy(
            RoleName='role-ec2-webserver',
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
        )
        iam.attach_role_policy(
            RoleName='role-ec2-webserver',
            PolicyArn='arn:aws:iam::aws:policy/CloudWatchLogsFullAccess'
        )
        print(f"   ✅ Created with S3 Read + CloudWatch Logs")
    except iam.exceptions.EntityAlreadyExistsException:
        print("   ⏭️  Already exists, skipping")
    
    print("\n" + "="*60)
    print("✅ Test NHIs created!")
    print("="*60)
    print("\nNow run 'python src/discovery.py' again to see them.")


if __name__ == "__main__":
    create_test_nhis()