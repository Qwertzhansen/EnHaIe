"""
NHI Discovery Tool - Phase 1
Findet alle Non-Human Identities in einem AWS Account
"""

import logging

import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def get_aws_client(service_name: str):
    """Erstellt einen AWS Client für einen Service"""
    return boto3.client(service_name)


def calculate_age_days(creation_date: Optional[datetime]) -> Optional[int]:
    """Berechnet wie alt etwas ist in Tagen"""
    if creation_date is None:
        return None
    now = datetime.now(timezone.utc)
    age = now - creation_date
    return age.days


def discover_iam_users() -> list[dict]:
    """
    Findet alle IAM Users und ihre Access Keys

    IAM Users können Menschen sein, aber oft sind sie Service Accounts
    (erkennbar an Namen wie 'svc-', 'bot-', 'service-', etc.)
    """
    logger.info("Starte IAM-User-Discovery")

    iam = get_aws_client('iam')
    users = iam.list_users()['Users']

    results = []

    for user in users:
        username = user['UserName']
        created = user['CreateDate']
        age_days = calculate_age_days(created)

        # Access Keys für diesen User holen
        access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

        # Letzte Nutzung prüfen
        try:
            last_used_response = iam.get_user(UserName=username)
            password_last_used = last_used_response['User'].get('PasswordLastUsed')
        except ClientError as exc:
            logger.warning("Konnte PasswordLastUsed für %s nicht abrufen: %s", username, exc)
            password_last_used = None

        # Attached Policies (Berechtigungen) holen
        attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        policy_names = [p['PolicyName'] for p in attached_policies]

        user_info = {
            'type': 'IAM_USER',
            'name': username,
            'created': created.isoformat(),
            'age_days': age_days,
            'access_key_count': len(access_keys),
            'policies': policy_names,
            'password_last_used': password_last_used.isoformat() if password_last_used else 'Never',
        }

        # Access Key Details
        for i, key in enumerate(access_keys):
            key_id = key['AccessKeyId']
            key_created = key['CreateDate']
            key_status = key['Status']

            # Wann wurde der Key zuletzt benutzt?
            key_last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
            last_used_date = key_last_used['AccessKeyLastUsed'].get('LastUsedDate')

            user_info[f'access_key_{i+1}_id'] = key_id
            user_info[f'access_key_{i+1}_age_days'] = calculate_age_days(key_created)
            user_info[f'access_key_{i+1}_status'] = key_status
            user_info[f'access_key_{i+1}_last_used'] = last_used_date.isoformat() if last_used_date else 'Never'

        results.append(user_info)
        logger.debug("IAM User gefunden: %s (Alter: %s Tage, Keys: %d)", username, age_days, len(access_keys))

    logger.info("IAM-User-Discovery abgeschlossen: %d Users gefunden", len(results))
    return results


def discover_iam_roles() -> list[dict]:
    """
    Findet alle IAM Roles

    Roles sind fast immer NHIs - sie werden von Services,
    Lambda Functions, EC2 Instances etc. genutzt
    """
    logger.info("Starte IAM-Role-Discovery")

    iam = get_aws_client('iam')
    roles = iam.list_roles()['Roles']

    results = []

    for role in roles:
        role_name = role['RoleName']
        created = role['CreateDate']
        age_days = calculate_age_days(created)

        # AWS Service Roles rausfiltern (die sind von AWS selbst)
        path = role.get('Path', '/')
        is_aws_service_role = path.startswith('/aws-service-role/')

        if is_aws_service_role:
            continue  # Überspringen - das sind AWS-interne Roles

        # Wer darf diese Role annehmen?
        assume_role_policy = role.get('AssumeRolePolicyDocument', {})

        # Attached Policies holen
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        policy_names = [p['PolicyName'] for p in attached_policies]

        # Letzte Nutzung
        try:
            last_used_response = iam.get_role(RoleName=role_name)
            last_used = last_used_response['Role'].get('RoleLastUsed', {})
            last_used_date = last_used.get('LastUsedDate')
        except ClientError as exc:
            logger.warning("Konnte RoleLastUsed für %s nicht abrufen: %s", role_name, exc)
            last_used_date = None

        role_info = {
            'type': 'IAM_ROLE',
            'name': role_name,
            'created': created.isoformat(),
            'age_days': age_days,
            'policies': policy_names,
            'last_used': last_used_date.isoformat() if last_used_date else 'Never',
        }

        results.append(role_info)
        logger.debug("IAM Role gefunden: %s (Alter: %s Tage)", role_name, age_days)

    logger.info("IAM-Role-Discovery abgeschlossen: %d Roles gefunden", len(results))
    return results


def main() -> list[dict]:
    """Hauptfunktion - startet die Discovery"""
    logger.info("NHI Discovery Tool gestartet")

    all_nhis = []

    # IAM Users scannen
    users = discover_iam_users()
    all_nhis.extend(users)

    # IAM Roles scannen
    roles = discover_iam_roles()
    all_nhis.extend(roles)

    logger.info(
        "Discovery abgeschlossen: %d Users, %d Roles, %d NHIs gesamt",
        len(users), len(roles), len(all_nhis),
    )

    return all_nhis


if __name__ == "__main__":
    results = main()