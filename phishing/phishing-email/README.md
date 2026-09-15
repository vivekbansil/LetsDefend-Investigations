# Phishing Email

**Platform:** LetsDefend  
**Category:** Phishing Analysis  
**Difficulty:** Easy  
**Environment:** Simulated security investigation

## Overview

This investigation involved a suspicious PayPal-themed email written in German.

I analyzed the original email file, reviewed message headers and sender information, inspected the embedded link, and used external threat intelligence to evaluate the infrastructure associated with the message.

The main goal was to determine whether the email was legitimate or part of a phishing attempt while separating what the artifacts directly showed from what required additional investigation.

## Evidence Sources

The investigation included:

- Original `.eml` file
- Email headers
- Email body and embedded URL
- Sender and return-path information
- URL and domain information
- Threat intelligence results

## Tools Used

- Mozilla Thunderbird
- VirusTotal
- Browser-based URL and domain research

## Skills Practiced

- Email header analysis
- Phishing triage
- Sender and return-path review
- URL analysis
- IOC identification
- Threat intelligence interpretation
- SHA-256 hash interpretation
- MITRE ATT&CK mapping

## Key Takeaway

The main lesson from this investigation was that one suspicious indicator should not automatically determine the verdict.

The email became more convincing as a phishing attempt after multiple pieces of evidence were considered together, including the message context, sender information, embedded link, hosting location, and threat intelligence.

I also learned that a legitimate hosting provider should not automatically be treated as malicious simply because an attacker abuses content hosted on its infrastructure.

See [investigation-summary.md](investigation-summary.md) for the investigation methodology and findings.

## Spoiler Notice

Specific challenge answers, hashes, email addresses, and malicious URLs have been intentionally omitted.

