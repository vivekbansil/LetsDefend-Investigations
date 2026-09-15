```markdown
# LetsDefend Security Investigations

This repository documents selected hands-on security investigations completed through LetsDefend.

The purpose of these writeups is to show how I approach security evidence, build timelines, correlate activity across different artifacts, and document conclusions. I am using these labs to strengthen practical blue-team skills alongside my previous Hack The Box Sherlock investigations.

The investigations are performed in simulated environments and are intended for learning and portfolio development. I avoid publishing challenge flags, direct answer strings, or unnecessary spoilers.

## Investigation Areas

### Phishing

- **Phishing Email**  
  Analyzed a phishing email, inspected message artifacts and embedded links, and used threat intelligence to evaluate the infrastructure associated with the message.

- **Phantom Validation**  
  Reconstructed a payroll-themed intrusion involving a redirected download, archive extraction, command-script execution, abuse of a native Windows utility, and retrieval of additional external content. The investigation required correlation across browser artifacts, NTFS metadata, Prefetch, and server-side HTTP logs.

### Detection

- **Learn Sigma**  
  Reviewed and interpreted Sigma detection logic for suspicious use of a Windows native utility, including rule structure, log sources, matching conditions, false positives, and MITRE ATT&CK context.

## Skills Practiced

Across these investigations I have worked with:

- Phishing and URL analysis
- Browser history and download artifacts
- Windows Prefetch
- NTFS Master File Table (`$MFT`)
- NTFS USN Journal (`$J`)
- Mark of the Web / `Zone.Identifier`
- HTTP access logs
- Timeline reconstruction
- Native Windows utility abuse
- IOC identification and correlation
- Sigma detection logic
- MITRE ATT&CK mapping
- PowerShell-based forensic triage
- Evidence-based documentation

## Investigation Approach

I try to separate what an artifact directly proves from what I am inferring from it.

My general workflow is:

1. Establish the available evidence sources.
2. Identify an initial activity or indicator worth investigating.
3. Pivot into related host, filesystem, browser, or network artifacts.
4. Build a timeline around confirmed activity.
5. Correlate findings across more than one source when possible.
6. Separate observations from hypotheses and conclusions.
7. Document both the findings and any limitations in the evidence.

One lesson I have been reinforcing throughout these labs is that the presence of a suspicious filename or process is not automatically proof of malicious execution. Stronger conclusions come from correlating several artifacts that describe different parts of the same activity.

## Disclaimer

These investigations were completed in controlled training environments. The writeups intentionally omit challenge answers, flags, and some identifying indicators so that they demonstrate methodology without serving as solution guides.
```
