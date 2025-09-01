# Hardening-Amazon-IAM-for-Cloud-Engineers
A practical example of CVE‑2022‑1524 that illustrates the attack path and provides actionable remediation scripts, and puts forward unconventional detection logic

In today’s cloud-first world, Identity and Access Management (IAM) is the gatekeeper to everything. But even the most seasoned cloud engineers can find themselves navigating a minefield of misconfigurations and overlooked vulnerabilities. This article dives into a real-world example of CVE‑2022‑1524, not just to explain how the attack works, but to empower you with practical scripts and unconventional detection logic that go beyond the basics.

Whether you're a cloud architect tightening your defenses or a security enthusiast curious about IAM exploits, this guide offers a hands-on approach to understanding and mitigating threats before they become headlines.

CVE‑2022‑1524 highlights a scenario where stale or improperly rotated access keys can be leveraged by attackers to gain unauthorized access to AWS resources. Think of it like leaving a spare key under the doormat and forgetting it’s there—except in this case, the doormat is the cloud, and the key could unlock sensitive infrastructure.Rotating access keys regularly is one of those best practices that’s easy to overlook. When keys sit around unused or unchanged for months, they become the low-hanging fruit for attackers. Especially if those keys are hardcoded in scripts, buried in old repositories, or tied to users who’ve left the team.

This article aims to equips you with practical, ready-to-use scripts that help you detect stale access keys, audit IAM configurations, and apply unconventional logic to uncover hidden vulnerabilities.

#!/usr/bin/env python3
"""
iam_hardening_exploit.py

Author:   Mark Mallia
Date:     2023‑02‑15

Purpose
-------
* Detect IAM roles that have an access key older than the threshold you care about.  
* Check whether those roles already contain a rotation policy; if not – add it.  
* Log every action so you can audit later, and push the changes back to your repo.

import json
import logging
from datetime import datetime, timedelta

# --------------------------------------------------------------------------- #
#  Helper: list IAM roles + their access keys
# --------------------------------------------------------------------------- #
def list_roles_and_keys() -> dict:
    """
    Return a dictionary of {role_name : [access_key_id, create_date]}

    The `boto3` client will be reused for every role so that we only hit the API
    once per account – this keeps the runtime low.
    """
    import boto3

    iam = boto3.client('iam')
    roles_map: dict[str, list[tuple]] = {}

    # fetch all existing IAM roles
    for role in iam.list_roles()['Roles']:
        name = role['RoleName']

        # fetch every key that belongs to this role
        keys_meta = iam.list_access_keys(UserName=name)['AccessKeyMetadata']
        for key_meta in keys_meta:
            roles_map.setdefault(name, []).append(
                (key_meta['AccessKeyId'],
                 datetime.strptime(key_meta['CreateDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
                )
    return roles_map

# --------------------------------------------------------------------------- #
#  Helper: filter out stale roles
# --------------------------------------------------------------------------- #
def find_stale_roles(roles: dict, threshold_days: int) -> list[str]:
    """
    Return a list of role names that have no key newer than `threshold_days`.
    The function assumes that the newest key in `roles` represents the current
    active credential for that role.
    """
    stale = []
    now = datetime.utcnow()
    for name, keys in roles.items():
        latest_key_date = max(k[1] for k in keys)
        if (now - latest_key_date).days > threshold_days:
            stale.append(name)
    return stale

# --------------------------------------------------------------------------- #
# Helper: check whether rotation policy exists
# --------------------------------------------------------------------------- #
def missing_rotation_policies(stale_roles: list[str]) -> list[tuple]:
    """
    Return a list of (role_name, policy_arn) tuples for roles that lack an
    `auto_rotation` policy.  The ARN is constructed on‑the‑fly so that the
    policy can be attached without manual intervention.
    """
    import boto3
    iam = boto3.client('iam')

    missing = []
    for role_name in stale_roles:
        # look up every policy that already exists on this role
        policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        names = [p['PolicyName'] for p in policies]

        if 'auto_rotation' not in names:
            missing.append((role_name, f"arn:aws:iam:::{role_name}"))
    return missing

# --------------------------------------------------------------------------- #
#  Helper: write the rotation policy
# --------------------------------------------------------------------------- #
def apply_rotation_policy(role_name: str) -> None:
    """
    Create (or overwrite) a single IAM policy named `auto_rotation` on the role.
    The policy covers both IAM actions and an S3 bucket that stores the role’s data,
    so that we keep all needed permissions in one place.
    """
    import boto3
    iam = boto3.client('iam')

    rotation_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey", "iam:GetUser"],
                "Resource": [f"arn:aws:iam:::{role_name}"]
            },
            {
                "Effect": "Allow",

# Detection Strategies & IAM Hardening

Beyond rotating keys we also need to put in place detection logic (Cloud Watch) to alert us if the scripts fail to run. 

**Alerting if keys exceed 90 days** 

aws logs put-metric-filter \
  --log-group-name "/aws/iam" \
  --filter-pattern '"{\"Action\":\"iam:CreateAccessKey\",\"UserName\":\"*\"}"' \
  --metric-transformations "MetricValue=1,MetricNamespace=IAM,MetricName=KeyAge"


add an alarm 

aws cloudwatch put-metric-alarm \
  --alarm-name 'IAM‑Key‑Rotation‑Alarm' \
  --metric-name KeyAge \
  --namespace IAM \
  --statistic Sum \
  --period 86400 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold



              
