#!/usr/bin/env python3
"""
BTCMP Cloud Forensics mini-lab — synthetic dataset generator.

Produces two internally-consistent evidence files:
  - s3_access.log   : S3 server access logs (space-delimited, data plane)
  - cloudtrail.json : CloudTrail management/IAM events (JSON, control plane)

Deterministic (seeded). Re-run to regenerate identical output.
Edit the CONFIG block to change the planted storyline / flag values.
"""

import json
import random
import string
from datetime import datetime, timedelta, timezone

random.seed(1337)

# ----------------------------------------------------------------------------
# CONFIG  (flag values + scenario constants)
# ----------------------------------------------------------------------------
ACCOUNT_ID        = "123456789012"
ATTACKER_IP       = "203.0.113.77"                 # FLAG 1
COMPROMISED_USER  = "svc-backup-dev"               # FLAG 2
RECON_TIME        = "2026-05-14T02:17:43Z"         # FLAG 3 (ListBuckets)
TARGET_BUCKET     = "acme-hr-records-prod"         # FLAG 4
EXFIL_OBJECTS     = 47                              # FLAG 5
NEW_KEY_ID        = "AKIA5EXAMPLE7XQ2R9KD"          # FLAG 6 (CreateAccessKey)

COMPROMISED_KEY   = "AKIAIOSFODNN7EXAMPLE"          # key the attacker is abusing
CORP_EGRESS_NET   = "198.51.100."                   # legit office egress /24
REGION_HOME       = "eu-west-1"                      # company's normal region
REGION_ATTACK     = "eu-west-1"                      # data plane stays same region

BENIGN_S3_LINES   = 2500
BENIGN_CT_EVENTS  = 48

BUCKETS = [
    "acme-hr-records-prod",   # the target (sensitive)
    "acme-app-assets",
    "acme-backups",
    "acme-logs-archive",
    "acme-web-static",
]

LEGIT_PRINCIPALS = [
    ("IAMUser", "jdoe",        "AIDAJDOE00000EXAMPLE", "AKIAJDOE0000000EXMPL"),
    ("IAMUser", "msmith",      "AIDAMSMITH000EXAMPLE", "AKIAMSMITH00000EXMPL"),
    ("IAMUser", "kpatel",      "AIDAKPATEL000EXAMPLE", "AKIAKPATEL00000EXMPL"),
    ("AssumedRole", "app-backend", "AROAAPPBACKENDEXAMPLE", "ASIAAPPBACKEND0EXMPL"),
    ("AssumedRole", "ci-runner",   "AROACIRUNNER00EXAMPLE", "ASIACIRUNNER000EXMPL"),
]

BUCKET_OWNER = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

UA_LEGIT = [
    "aws-cli/2.15.30 Python/3.11.6 Linux/6.1.0 botocore/2.4.5",
    "Boto3/1.34.11 md/Botocore#1.34.11 ua/2.0 os/linux lang/python#3.11.6",
    "S3Console/0.4",
    "aws-sdk-java/2.25.1 Linux/5.15 OpenJDK_64-Bit_Server_VM/17.0.10",
]
UA_ATTACKER = "aws-cli/2.13.0 Python/3.9.2 Linux/5.4.0 botocore/2.2.0"

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def rid(n):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

def hexid(n):
    return "".join(random.choices("abcdef0123456789", k=n))

def corp_ip():
    return CORP_EGRESS_NET + str(random.choice([10, 11, 12, 13, 25, 26, 40]))

def arn_for(ptype, name):
    if ptype == "AssumedRole":
        return f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{name}/session-{rid(6)}"
    return f"arn:aws:iam::{ACCOUNT_ID}:user/{name}"

def s3_time(dt):
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0000]")

def ct_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def s3_line(dt, ip, requester_arn, op, key, status, bytes_sent, obj_size, ua, bucket):
    parts = [
        BUCKET_OWNER,
        bucket,
        s3_time(dt),
        ip,
        requester_arn,
        rid(16),                       # Request ID
        op,
        key if key else "-",
        f'"GET /{key} HTTP/1.1"' if key != "-" else '"GET / HTTP/1.1"',
        str(status),
        "-",                           # error code
        str(bytes_sent),
        str(obj_size),
        str(random.randint(8, 180)),   # total time ms
        str(random.randint(0, 40)),    # turn-around ms
        '"-"',
        f'"{ua}"',
        "-",                           # version id
        hexid(64) + "=",               # host id
        "SigV4",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "AuthHeader",
        f"{bucket}.s3.{REGION_HOME}.amazonaws.com",
        "TLSv1.2",
        "-",
    ]
    return " ".join(parts)

def ct_event(dt, ptype, name, principal_id, arn, access_key, ip, event_source,
             event_name, ua, req_params=None, resp_elems=None, region=REGION_HOME):
    rec = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": ptype,
            "principalId": principal_id,
            "arn": arn,
            "accountId": ACCOUNT_ID,
            "accessKeyId": access_key,
        },
        "eventTime": ct_time(dt),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": req_params,
        "responseElements": resp_elems,
        "requestID": rid(16),
        "eventID": f"{hexid(8)}-{hexid(4)}-{hexid(4)}-{hexid(4)}-{hexid(12)}",
        "readOnly": event_name.startswith(("List", "Get", "Describe", "Head")),
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": ACCOUNT_ID,
    }
    if ptype == "IAMUser":
        rec["userIdentity"]["userName"] = name_from_arn(arn)
    return rec

def name_from_arn(arn):
    return arn.split("/")[-1]

# ----------------------------------------------------------------------------
# benign S3 traffic
# ----------------------------------------------------------------------------
s3_lines = []
base = datetime(2026, 5, 13, 6, 0, 0, tzinfo=timezone.utc)

for _ in range(BENIGN_S3_LINES):
    # business-hours-weighted timestamp across two days
    day_offset = random.choice([0, 0, 1, 1, 1])
    hour = int(random.triangular(7, 19, 13))
    dt = base + timedelta(days=day_offset,
                          hours=hour - 6,
                          minutes=random.randint(0, 59),
                          seconds=random.randint(0, 59))
    ptype, name, pid, akey = random.choice(LEGIT_PRINCIPALS)
    arn = arn_for(ptype, name)
    bucket = random.choices(BUCKETS, weights=[1, 5, 3, 4, 6])[0]  # HR bucket rarely touched
    op = random.choices(
        ["REST.GET.OBJECT", "REST.PUT.OBJECT", "REST.HEAD.OBJECT", "REST.GET.BUCKET"],
        weights=[6, 2, 2, 1])[0]
    key = f"{random.choice(['data','img','rep','cfg','bak'])}/{hexid(8)}.{random.choice(['json','png','csv','log','gz'])}"
    if op == "REST.GET.BUCKET":
        key = "-"
    size = random.randint(512, 5_000_000)
    sent = size if op.endswith("OBJECT") and op.startswith("REST.GET") else 0
    s3_lines.append((dt, s3_line(dt, corp_ip(), arn, op, key, 200, sent, size,
                                 random.choice(UA_LEGIT), bucket)))

# legit svc-backup-dev nightly job -> acme-backups only, from corp IP
for _ in range(40):
    dt = base + timedelta(days=random.choice([0, 1]),
                          hours=random.choice([1, 2, 3]) - 6,
                          minutes=random.randint(0, 59),
                          seconds=random.randint(0, 59))
    arn = arn_for("IAMUser", COMPROMISED_USER)
    key = f"snapshots/{hexid(10)}.tar.gz"
    size = random.randint(1_000_000, 80_000_000)
    s3_lines.append((dt, s3_line(dt, corp_ip(), arn, "REST.PUT.OBJECT", key, 200,
                                 0, size, UA_LEGIT[1], "acme-backups")))

# ----------------------------------------------------------------------------
# MALICIOUS S3 traffic — 47 GETs from attacker on the HR bucket
# ----------------------------------------------------------------------------
arn_attacker = arn_for("IAMUser", COMPROMISED_USER)
exfil_start = datetime(2026, 5, 14, 2, 19, 4, tzinfo=timezone.utc)
hr_keys = [
    "payroll/2026/Q1_salaries.xlsx",
    "payroll/2026/Q2_salaries.xlsx",
    "employees/ssn_master.csv",
    "employees/passport_scans.zip",
    "benefits/health_enrollment.csv",
    "contracts/exec_compensation.pdf",
    "performance/review_2025.csv",
]
for i in range(EXFIL_OBJECTS):
    dt = exfil_start + timedelta(seconds=i * random.randint(4, 7))
    base_key = random.choice(hr_keys)
    key = base_key if i < len(hr_keys) else f"{base_key.rsplit('.',1)[0]}_{i}.{base_key.rsplit('.',1)[1]}"
    size = random.randint(40_000, 9_500_000)
    s3_lines.append((dt, s3_line(dt, ATTACKER_IP, arn_attacker, "REST.GET.OBJECT",
                                 key, 200, size, size, UA_ATTACKER, TARGET_BUCKET)))

# sort chronologically and write
s3_lines.sort(key=lambda x: x[0])
with open("s3_access.log", "w") as f:
    f.write("\n".join(line for _, line in s3_lines) + "\n")

# ----------------------------------------------------------------------------
# benign CloudTrail events
# ----------------------------------------------------------------------------
ct = []
for _ in range(BENIGN_CT_EVENTS):
    day_offset = random.choice([0, 0, 1, 1, 1])
    hour = int(random.triangular(7, 19, 13))
    dt = base + timedelta(days=day_offset, hours=hour - 6,
                          minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    ptype, name, pid, akey = random.choice(LEGIT_PRINCIPALS)
    arn = arn_for(ptype, name)
    name_evt, src = random.choice([
        ("ConsoleLogin", "signin.amazonaws.com"),
        ("ListBuckets", "s3.amazonaws.com"),
        ("GetBucketLocation", "s3.amazonaws.com"),
        ("DescribeInstances", "ec2.amazonaws.com"),
        ("GetCallerIdentity", "sts.amazonaws.com"),
        ("AssumeRole", "sts.amazonaws.com"),
        ("HeadBucket", "s3.amazonaws.com"),
        ("DescribeRegions", "ec2.amazonaws.com"),
    ])
    ct.append(ct_event(dt, ptype, name_evt, pid, arn, akey, corp_ip(),
                       src, name_evt, random.choice(UA_LEGIT)))

# one benign failed console login red herring (legit user, corp IP, typo'd password)
ct.append(ct_event(datetime(2026, 5, 13, 8, 41, 9, tzinfo=timezone.utc),
                   "IAMUser", "ConsoleLogin", "AIDAMSMITH000EXAMPLE",
                   arn_for("IAMUser", "msmith"), "AKIAMSMITH00000EXMPL",
                   corp_ip(), "signin.amazonaws.com", "ConsoleLogin",
                   UA_LEGIT[2], resp_elems={"ConsoleLogin": "Failure"}))

# ----------------------------------------------------------------------------
# MALICIOUS CloudTrail chain (control / IAM plane)
# ----------------------------------------------------------------------------
arn_c = arn_for("IAMUser", COMPROMISED_USER)
pid_c = "AIDASVCBACKUPDEVEXAMPLE"

# 1. recon: ListBuckets  (FLAG 3)
ct.append(ct_event(datetime.fromisoformat(RECON_TIME.replace("Z", "+00:00")),
                   "IAMUser", "ListBuckets", pid_c, arn_c, COMPROMISED_KEY,
                   ATTACKER_IP, "s3.amazonaws.com", "ListBuckets", UA_ATTACKER))

# 2. enumerate target ACL / policy
ct.append(ct_event(datetime(2026, 5, 14, 2, 18, 5, tzinfo=timezone.utc),
                   "IAMUser", "GetBucketAcl", pid_c, arn_c, COMPROMISED_KEY,
                   ATTACKER_IP, "s3.amazonaws.com", "GetBucketAcl", UA_ATTACKER,
                   req_params={"bucketName": TARGET_BUCKET}))
ct.append(ct_event(datetime(2026, 5, 14, 2, 18, 31, tzinfo=timezone.utc),
                   "IAMUser", "GetBucketPolicy", pid_c, arn_c, COMPROMISED_KEY,
                   ATTACKER_IP, "s3.amazonaws.com", "GetBucketPolicy", UA_ATTACKER,
                   req_params={"bucketName": TARGET_BUCKET}))

# 3. persistence: CreateAccessKey  (FLAG 6)
ct.append(ct_event(datetime(2026, 5, 14, 2, 31, 12, tzinfo=timezone.utc),
                   "IAMUser", "CreateAccessKey", pid_c, arn_c, COMPROMISED_KEY,
                   ATTACKER_IP, "iam.amazonaws.com", "CreateAccessKey", UA_ATTACKER,
                   req_params={"userName": COMPROMISED_USER},
                   resp_elems={"accessKey": {
                       "accessKeyId": NEW_KEY_ID,
                       "status": "Active",
                       "userName": COMPROMISED_USER,
                       "createDate": "May 14, 2026 2:31:12 AM"}}))

# sort by eventTime and write CloudTrail
ct.sort(key=lambda r: r["eventTime"])
with open("cloudtrail.json", "w") as f:
    json.dump({"Records": ct}, f, indent=2)

# ----------------------------------------------------------------------------
# summary to stdout
# ----------------------------------------------------------------------------
print(f"s3_access.log    : {len(s3_lines)} lines "
      f"({EXFIL_OBJECTS} malicious GETs from {ATTACKER_IP})")
print(f"cloudtrail.json  : {len(ct)} events "
      f"(4 malicious: ListBuckets, GetBucketAcl, GetBucketPolicy, CreateAccessKey)")
