# Phantom Validation

**Platform:** LetsDefend  
**Category:** Phishing / Endpoint Investigation  
**Difficulty:** Easy  
**Environment:** Simulated Windows endpoint investigation

## Overview

Phantom Validation began with a payroll-themed phishing lure that directed the victim through a shortened URL to an externally hosted archive.

The investigation went beyond analyzing the initial phishing link. I reconstructed activity from the browser download through archive extraction, command-script creation, native Windows utility execution, external resource retrieval, and the creation and deletion of a short-lived file.

This investigation required correlating evidence across browser artifacts, NTFS filesystem metadata, Windows Prefetch, and server-side HTTP logs.

## Evidence Sources

The investigation included:

- Chromium-based browser history and download databases
- Browser profile configuration artifacts
- HTTP access logs
- NTFS USN Journal (`$J`)
- NTFS Master File Table (`$MFT`)
- Windows Prefetch
- NTFS alternate data streams
- Filesystem metadata from a Windows forensic triage collection

## Tools Used

- PowerShell
- DB Browser for SQLite
- Eric Zimmerman MFTECmd
- Eric Zimmerman PECmd

## Skills Practiced

- Browser artifact analysis
- Redirect and download-chain reconstruction
- NTFS timeline analysis
- USN Journal parsing
- MFT record inspection
- Windows Prefetch analysis
- Mark of the Web identification
- Native Windows utility analysis
- HTTP log analysis
- EPOCH timestamp conversion
- Multi-source timeline correlation

## Key Takeaway

The most useful part of this investigation was learning not to treat a single artifact as the entire answer.

A suspicious filename first became a candidate. Filesystem metadata established when it appeared, Prefetch helped establish execution context, and HTTP logs provided network-side evidence. Correlating those sources produced a much stronger conclusion than relying on any one artifact by itself.

See [investigation-summary.md](investigation-summary.md) for the technical investigation notes.

## Spoiler Notice

Specific challenge answers, flags, and selected indicators have been intentionally omitted.
