# Learn Sigma — Investigation Summary

## Overview

This challenge focused on interpreting a Sigma rule designed to identify suspicious `bitsadmin.exe` download activity.

BITSAdmin is a legitimate Windows command-line utility used to interact with the Background Intelligent Transfer Service (BITS). Because BITS can transfer files in the background, attackers can also abuse the functionality to retrieve malicious content.

The objective of this exercise was not to investigate an endpoint compromise directly. Instead, it was to understand how a Sigma rule represents suspicious behavior and how each part of the rule contributes to detection.

## Investigation Objective

The main goals were to understand:

- what behavior the rule was intended to detect;
- which log source the rule expected;
- how selections describe matching events;
- how the `condition` determines when the rule triggers;
- why metadata and tags are useful;
- how false positives should be considered; and
- how the behavior maps to MITRE ATT&CK.

## Sigma Rule Components

### Metadata

The rule metadata provides information describing the detection.

Depending on the rule, this can include:

- title;
- description;
- author;
- creation or modification dates;
- rule status;
- severity level; and
- references or tags.

Metadata does not normally determine whether an event matches the rule.

Instead, it helps analysts understand the purpose and context of the detection.

### Log Source

The `logsource` section identifies the type of telemetry the detection expects.

For a process-creation rule, the detection needs events containing information about executed processes and their associated fields.

This reinforced an important detection concept:

> A rule is only useful when the required telemetry actually exists.

A well-written process detection cannot identify activity if process-execution events are not being collected.

### Detection Selections

The `detection` section contained criteria describing the behavior of interest.

Selections can examine fields such as:

- process image;
- executable name;
- command-line content; and
- arguments or keywords associated with the behavior.

The rule used these criteria to recognize BITSAdmin activity consistent with downloading files.

### Condition

The `condition` determines how the selections must relate before an event becomes a match.

This was one of the most important concepts from the challenge.

Selections describe individual pieces of evidence.

The condition expresses the actual logic.

Conceptually:

```text
selection A
AND
selection B
````

is different from:

```text
selection A
OR
selection B
```

Even if the selections are identical, changing the condition can substantially change what the rule detects and how many false positives it produces.

### Fields

The `fields` section identifies information useful to display when the detection triggers.

These fields can give an analyst additional context for triage.

They should not be confused with the matching condition itself.

A field can be useful to display without being part of the logic that caused the alert.

### False Positives

BITSAdmin and BITS are legitimate Windows functionality.

Therefore:

```text
bitsadmin.exe executed
```

does not automatically mean:

```text
malicious activity
```

Legitimate administrators, software components, or maintenance processes may use similar functionality.

A detection should therefore provide enough context for an analyst to investigate why the utility executed and what it attempted to transfer.

### Severity

The rule also contained a severity level.

Severity provides an indication of how the rule author expects the detection to be prioritized, but it does not prove that an individual match is malicious.

The final verdict still depends on investigation and surrounding context.

## Native Utility Abuse

An important concept introduced by this challenge was the abuse of legitimate Windows utilities.

`bitsadmin.exe` is not malware.

The suspicious behavior comes from how the utility is used.

BITS can perform background file transfers, which means an attacker may use existing Windows functionality instead of introducing a custom downloader.

This is part of the broader idea of living off the land:

```text
use functionality already present on the endpoint
        ↓
perform behavior useful to the attacker
```

This concept later became useful during other investigations where native Windows utilities appeared inside suspicious execution chains.

## MITRE ATT&CK Mapping

The primary ATT&CK behavior associated with the rule was:

| Activity                                              | ATT&CK Mapping                |
| ----------------------------------------------------- | ----------------------------- |
| Abuse of Background Intelligent Transfer Service jobs | BITS Jobs — T1197             |
| Retrieval of additional content using BITS            | Ingress Tool Transfer context |

BITSAdmin itself is a legitimate Windows tool rather than a technique.

The relevant ATT&CK mapping describes the behavior performed through the utility.

## Detection Reasoning

The rule demonstrated an important difference between weak and stronger detection logic.

A weak rule might alert whenever:

```text
bitsadmin.exe
```

appears.

That would potentially generate unnecessary alerts because the binary itself is legitimate.

A more meaningful detection attempts to identify:

```text
BITSAdmin execution
        +
arguments or behavior associated with file retrieval
```

This moves the detection from simple tool identification toward behavioral detection.

## Investigation Questions an Analyst Could Ask

If this rule triggered in a SOC environment, useful follow-up questions would include:

* Which user executed the process?
* What was the parent process?
* What command line was used?
* What remote destination was contacted?
* What file was downloaded?
* Where was the file written?
* Did the downloaded file execute afterward?
* Was this activity expected for the user or host?
* Did related alerts occur before or after the event?

These questions would help determine whether the detection represented legitimate administration or malicious activity.

## Detection Opportunities

Potential improvements or related detections could include correlating BITS activity with:

* suspicious parent processes;
* unusual remote destinations;
* newly created executables or scripts;
* execution from user-writable directories;
* subsequent process creation from downloaded content;
* unusual persistence through long-running BITS jobs; and
* other suspicious events occurring in the same time window.

These ideas represent investigative opportunities rather than production-ready detection rules.

## Lessons Learned

### Sigma is designed to describe detections independently of one SIEM

One of the useful concepts behind Sigma is that detections can describe log behavior in a platform-independent format.

The rule still depends on having the correct underlying telemetry.

### The condition is the logic of the rule

Understanding the selections alone is not enough.

The `condition` determines which combinations of those selections actually produce a match.

### Detection does not equal verdict

A rule firing identifies behavior worth investigating.

It does not automatically establish that an endpoint is compromised.

False-positive context and surrounding telemetry still matter.

### Legitimate tools can become suspicious through behavior

The presence of a Windows-native executable should not automatically be considered malicious.

The better questions are:

```text
What launched it?
What arguments were used?
What did it access?
Where did it connect?
What happened next?
```

Those questions help distinguish expected administration from suspicious living-off-the-land activity.

## Final Assessment

The challenge provided an introduction to how Sigma rules translate suspicious behavior into structured detection logic.

By reviewing the metadata, log source, selections, conditions, fields, false positives, severity, and ATT&CK context, I gained a better understanding of how a detection rule communicates both what should match and why an analyst should care about the resulting alert.

This was an introductory rule-analysis exercise rather than production detection-engineering experience, but it provided a useful foundation for understanding detection logic and alert triage.
