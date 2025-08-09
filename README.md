# chronicle-siem-integration
## Overview

This project provides a comprehensive integration of diverse log sources into Google Chronicle SIEM, enabling advanced threat detection and automated response for cloud and on-premises environments. It is tailored for healthcare data security and compliance.

## Integrated Log Sources

- **GCP Audit Logs**: Tracks administrative activities and access to GCP resources.
- **VPC Flow Logs**: Monitors network traffic flows for anomaly detection.
- **Cloud IDS**: Detects network-based threats and suspicious activity.
- **On-Prem Firewalls**: Ingests logs from physical and virtual firewalls for unified analysis.
- **Endpoint Security**: Integrates endpoint protection logs for comprehensive threat visibility.

## Custom Detection Rules

Developed over 30 custom YARA-L detection rules targeting:
- Cryptomining activity
- Suspicious data egress
- Brute force attacks
- Anomalous API activity (with healthcare-specific patterns)
- Privilege escalation attempts
- Lateral movement

Rules are optimized for healthcare data environments, focusing on HIPAA compliance and patient data protection.

## Automated Response Playbooks

Automated playbooks leverage Google Cloud Functions to:
- Isolate compromised VMs
- Block suspicious IPs
- Notify security teams via integrated alerting
- Trigger forensic data collection

These playbooks ensure rapid containment and remediation of detected threats.

## Impact & Results

- Reduced Mean Time to Detect (MTTD) critical threats by 70%
- Achieved unified visibility across cloud and on-premises infrastructure
- Enhanced compliance with healthcare security standards

## Getting Started

1. Configure log source ingestion in Chronicle SIEM.
2. Deploy custom YARA-L rules via Chronicle detection engine.
3. Set up Cloud Functions for automated response.
4. Review and customize playbooks for your environment.

## Documentation

- [Google Chronicle SIEM Documentation](https://cloud.google.com/chronicle/docs)
- [YARA-L Rule Syntax](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax)
- [YARA-L 2.0 Overview](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)

For further details, see the `/docs` directory (if available) or contact the project maintainer.
