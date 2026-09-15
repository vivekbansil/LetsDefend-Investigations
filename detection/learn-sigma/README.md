# Learn Sigma

**Platform:** LetsDefend  
**Category:** Detection Engineering Fundamentals  
**Difficulty:** Easy  
**Environment:** Sigma rule analysis exercise

## Overview

This challenge introduced the structure and logic of a Sigma detection rule.

The provided rule focused on detecting suspicious use of `bitsadmin.exe` for file-download activity. Rather than simply identifying whether the rule was malicious or benign, I worked through the purpose of each section and how the sections combine to describe the behavior being detected.

## Topics Practiced

- Sigma rule structure
- Rule metadata
- Log source selection
- Detection selections
- Conditions
- Fields
- False-positive considerations
- Severity levels
- MITRE ATT&CK tags
- Windows native utility abuse
- Detection logic interpretation

## Key Takeaway

The most useful lesson was understanding that a detection rule is not just a list of suspicious strings.

A useful rule connects:

```text
log source
    ↓
observable behavior
    ↓
selection criteria
    ↓
condition
    ↓
analyst context
````

The rule should describe behavior worth investigating while also providing enough context to understand why legitimate activity may sometimes match.

See [investigation-summary.md](investigation-summary.md) for additional notes.

## Spoiler Notice

Specific challenge answers and unnecessary answer-key details have been omitted.

