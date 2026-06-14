# BTCMP-16 — Cloud Forensics Lab

applied to: BTCMP-16-Df12.3

**Module:** Cloud Forensics  
**Difficulty:** Intermediate  
**Duration:** 45 minutes  
**MITRE ATT&CK:** T1530, T1567

---

## Overview

Trainees analyze a synthetic AWS evidence package (S3 server access logs + CloudTrail management events) exported from a compromised customer account. The objective is to identify unauthorized cloud storage access, correlate API calls with IAM identities, and produce a short forensic summary.

No internet access or live AWS account is required. All analysis is performed locally on the evidence files using standard Linux CLI tools.

---

## Topology

| Host | Role | IP | Flavor |
|------|------|----|--------|
| cloudvm | Analysis workstation | 192.168.0.10 | c2_r4_d40 |

**OS:** Xubuntu 24.04 (Noble)  
**Credentials:** `user` / `Password123`

---

## Learning Objectives

- Analyze cloud storage access logs (S3 server access log format)
- Identify suspicious data access or exfiltration patterns
- Correlate events with IAM activity via CloudTrail

## Learning Outcomes

- Detect unauthorized access to cloud storage
- Correlate API calls with user identities and timestamps
- Produce a short forensic summary

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `awk` | Field extraction and byte summation from S3 logs |
| `grep` | Pattern filtering across both log sources |
| `sort` / `uniq -c` | Frequency analysis — top IPs, requesters, operations |
| `jq` | JSON querying of CloudTrail events |
| `cut`, `wc -l` | Supporting analysis |

---

## Evidence Package

Staged at `/home/user/evidence/` on `cloudvm` after provisioning:

```
evidence/
├── s3_access.log      # S3 server access logs (data plane)
├── cloudtrail.json    # CloudTrail events (control/IAM plane)
└── README.txt         # Baseline brief for trainees
```

**Source:** `files/cloud-logs.zip` — served directly from the repo.

The dataset is synthetic and deterministic (seeded). To regenerate:

```bash
python3 files/generate_dataset.py
```

---


## Flags

| # | Finding | Format |
|---|---------|--------|
| 1 | Anomalous source IP | IPv4 address |
| 2 | Compromised IAM username | string |
| 3 | Recon timestamp (ListBuckets, UTC) | ISO 8601 |
| 4 | Targeted S3 bucket | string |
| 5 | Number of objects exfiltrated | integer |
| 6 | Persistence access key ID | `AKIA…` string |

Full flag values and solve commands are in `files/ANSWER_KEY_instructor.txt`.

---

## Notes

- The attacker is **low-volume** by design — flag 1 is found by baseline comparison against the known corporate egress range (`198.51.100.0/24`), not by top-talker frequency ranking.
- S3 log timestamps are bracketed (`[14/May/2026:02:19:04 +0000]`) and occupy **two** whitespace-delimited fields — source IP is `$5`, requester ARN is `$6` in `awk`.
- One benign failed `ConsoleLogin` (user `msmith`, corporate IP, daytime) is a deliberate red herring.
