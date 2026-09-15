# Phishing Email — Investigation Summary

## Overview

This investigation involved a PayPal-themed email that appeared suspicious and required analysis of the original `.eml` file.

I reviewed the message using Mozilla Thunderbird, examined sender-related headers, inspected the embedded link, and used threat intelligence to determine whether the message was consistent with phishing activity.

Compared with later investigations involving Windows forensic artifacts, this was a smaller investigation, but it provided useful practice with the basic workflow for phishing-email triage.

---

## Investigation Objective

The primary goals were to determine:

- who appeared to send the message;
- which account received it;
- whether sender-related headers were consistent;
- where the embedded link led;
- whether the linked infrastructure had suspicious history;
- whether the message content could be identified using a known hash; and
- whether the available evidence supported a phishing verdict.

---

## Evidence Sources

### Original Email File

The provided `.eml` file was opened in Mozilla Thunderbird so that both the rendered message and underlying message information could be reviewed.

The message contained a PayPal-themed lure written in German and included a link intended to direct the recipient away from the email.

---

### Email Headers

Header analysis was used to review information including:

- sender address;
- recipient address;
- return-path;
- message routing information; and
- other metadata associated with delivery.

One useful lesson was that the visible sender field is only one part of an email investigation.

Fields such as `Return-Path` and the surrounding header context can provide additional evidence when evaluating whether a message is legitimate.

---

### Embedded URL

The email contained a link leading to externally hosted content.

Rather than assuming the entire hosting service was malicious, I separated:

```text
hosting provider
        ↓
specific hosted resource
````

A legitimate cloud or file-hosting service can be abused to host phishing content.

Therefore, the reputation of the provider alone was not enough to determine the verdict.

---

### Threat Intelligence

VirusTotal was used to research the URL and related indicators.

This introduced an important limitation of threat intelligence:

> Threat-intelligence results represent what providers knew at a particular point in time.

An indicator that is detected today may not have been detected when an incident originally occurred, and the reverse is also possible.

For that reason, threat intelligence was treated as supporting evidence rather than the only source used to determine whether the email was malicious.

---

## Investigation Methodology

### 1. Review the Email Context

I first examined the rendered email to understand the lure presented to the recipient.

The PayPal branding, language, and request for user interaction established the social-engineering context that would guide the rest of the investigation.

---

### 2. Inspect Sender Information

I reviewed the sender, recipient, and return-path information from the email.

The goal was not simply to copy individual addresses but to determine whether the identity represented to the user was consistent with the underlying email metadata.

Differences between visible branding and technical sender information contributed to the suspicious nature of the message.

---

### 3. Extract and Analyze the Link

The embedded URL was identified and separated into its relevant components.

I examined:

* the protocol;
* hostname;
* complete resource path; and
* hosting infrastructure.

This helped distinguish between the legitimate hosting platform and the specific resource being used as part of the phishing campaign.

---

### 4. Research the Indicator

The URL and related infrastructure were investigated using VirusTotal.

The results provided additional historical and reputation context.

I avoided treating a reputation score as an automatic verdict and instead combined the results with evidence from the original message.

---

### 5. Evaluate the Message Body Hash

The investigation also involved a SHA-256 value associated with the HTTP response body.

This helped reinforce the distinction between different types of hashes.

A response-body hash identifies the content returned by a web request. It should not automatically be interpreted as the hash of:

* the email itself;
* an attachment; or
* an executable payload.

Understanding what was actually hashed was necessary before using the value as an indicator.

---

## Key Findings

### Finding 1 — The message used a financial-services lure

The email impersonated a recognizable financial brand and attempted to direct the recipient to an external resource.

The brand name itself was not evidence that the message came from the legitimate organization.

---

### Finding 2 — Header analysis provided additional sender context

Reviewing the sender and return-path information showed why phishing analysis should go beyond the display name shown by the email client.

Technical header fields provided additional evidence for assessing the message.

---

### Finding 3 — The phishing content used legitimate hosting infrastructure

The suspicious resource was hosted using infrastructure belonging to a legitimate service provider.

This reinforced an important distinction:

```text
legitimate service
≠
every file or page hosted through that service is legitimate
```

Attackers can abuse reputable infrastructure to make malicious links appear less suspicious.

---

### Finding 4 — Threat intelligence supported the investigation but was time-dependent

Threat-intelligence information contributed additional context about the resource.

However, reputation and detection information can change over time, so it was used as supporting evidence rather than a substitute for analyzing the original email.

---

## MITRE ATT&CK Mapping

The behavior observed in the challenge was consistent with:

| Activity                                                 | ATT&CK Mapping                           |
| -------------------------------------------------------- | ---------------------------------------- |
| Phishing message containing a malicious external link    | Phishing: Spearphishing Link — T1566.002 |
| Victim encouraged to interact with the external resource | User Execution context                   |

The mapping is intentionally limited to behavior that was actually demonstrated in the available evidence.

---

## Detection Opportunities

Potential defensive opportunities include:

* identifying email messages that impersonate financial or account-related services;
* analyzing links whose visible context does not match their actual destination;
* inspecting redirect chains before allowing users to reach external content;
* correlating suspicious sender information with newly observed URLs;
* inspecting URLs hosted on commonly abused cloud or storage providers without blocking the entire provider; and
* combining email-security telemetry with threat-intelligence results.

---

## Lessons Learned

### Email analysis requires more than the visible sender

The address or display name shown by an email client is only one part of the message.

Sender-related headers and routing information can provide additional context.

---

### Legitimate infrastructure can host malicious content

A well-known domain or cloud provider does not automatically make an individual resource trustworthy.

The correct question is whether the specific content and activity are legitimate.

---

### Threat intelligence is temporal

VirusTotal and similar services provide valuable context, but detections can change as vendors learn more about an indicator.

Historical investigation should take this into account.

---

### Understand what a hash represents

A SHA-256 value is only useful when the analyst understands what object was hashed.

In this challenge, distinguishing an HTTP response-body hash from an email or attachment hash prevented an incorrect interpretation of the evidence.

---

## Final Assessment

The message was determined to be consistent with a phishing attempt.

The conclusion was based on the combination of the social-engineering lure, sender-related metadata, the embedded external resource, and supporting threat-intelligence information.

Although this was a relatively small investigation, it provided useful practice with the basic workflow of phishing triage and reinforced the importance of evaluating several indicators together rather than relying on a single suspicious field.

