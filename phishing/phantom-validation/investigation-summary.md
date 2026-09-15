# Phantom Validation — Investigation Summary

## Overview

This investigation involved a payroll-themed phishing chain that resulted in a ZIP archive being downloaded to a Windows endpoint.

The archive was later extracted and a command script was created on the system. I used browser artifacts, NTFS metadata, Windows Prefetch, and HTTP access logs to reconstruct what happened after the initial download and determine how additional external content was retrieved.

The investigation was completed using a forensic triage collection rather than a full live system or complete disk image, so conclusions were based on the artifacts available in the collection.

---

## Investigation Objective

The main goals were to determine:

- which user context was associated with the phishing activity;
- how the shortened phishing link resolved to the external download;
- where the archive was stored locally;
- which script appeared after extraction;
- when that script was created;
- whether it could be correlated with execution;
- which native Windows utility participated in the retrieval chain;
- which external resource was requested;
- which temporary file was created and deleted during the activity; and
- how the endpoint activity aligned with server-side HTTP records.

---

## Evidence Sources

### Browser Artifacts

Chromium-based browser artifacts were used to reconstruct the initial download activity.

Relevant sources included:

- browser `History` databases;
- `downloads`;
- `downloads_url_chains`;
- browser session artifacts; and
- browser profile configuration files.

The browser download chain was especially useful because it preserved the sequence between the original outbound link, the shortened URL, and the final archive location.

---

### HTTP Access Logs

The available HTTP access logs contained server-side request information including:

- client IP;
- HTTP method;
- host;
- URI;
- User-Agent;
- response status;
- response size; and
- EPOCH timestamps.

These logs were useful for corroborating both the original archive download and a later request for additional external content.

---

### NTFS USN Journal

The NTFS USN Journal (`$J`) was parsed with Eric Zimmerman's MFTECmd.

The USN Journal was particularly useful for identifying filesystem lifecycle events such as:

- `FileCreate`;
- `DataExtend`;
- `RenameOldName`;
- `RenameNewName`;
- `StreamChange`;
- `NamedDataExtend`; and
- `FileDelete`.

Rather than treating every row as a separate file, I grouped activity using filenames, paths, timestamps, and NTFS entry numbers.

---

### NTFS Master File Table

The `$MFT` was used to inspect specific NTFS records discovered during USN analysis.

This provided additional information such as:

- NTFS record numbers;
- file names;
- parent references;
- timestamps;
- data attributes;
- file size information; and
- alternate data streams.

One investigated command script contained a `Zone.Identifier` alternate data stream, which was consistent with Mark of the Web being associated with the file.

---

### Windows Prefetch

Windows Prefetch was parsed using Eric Zimmerman's PECmd.

Prefetch helped establish that relevant Windows executables had run during the incident window and showed file references associated with those executions.

This became important because filesystem creation alone could not prove that a script had actually participated in execution.

---

## Investigation Methodology

### 1. Establishing the Initial Download Chain

I first used browser artifacts to reconstruct how the victim reached the malicious archive.

The browser download database preserved multiple URL-chain entries associated with the same download. This allowed the redirect sequence to be reconstructed rather than relying on individual URL strings found elsewhere in the profile.

The chain showed a transition from an email-related outbound link to a URL shortener and finally to an externally hosted payroll-themed ZIP archive.

The browser's download table also identified the intended local destination of the archive under the victim user's Downloads directory.

This was useful because the logical Downloads directory itself was not preserved in the triage collection.

---

### 2. Validating the Archive Download with NTFS Records

The USN Journal showed the filesystem lifecycle associated with the downloaded archive.

Instead of immediately appearing under its final filename, the download moved through temporary Chromium download names before being renamed to the completed ZIP filename.

The observed pattern was generally:

```text
temporary file
    ↓
partial Chromium download
    ↓
final ZIP filename
````

This helped explain why the final ZIP filename did not have its own standalone `FileCreate` event.

The underlying filesystem object had already been created under a temporary name and was later renamed.

---

### 3. Identifying the Extracted Command Script

I searched USN activity shortly after the archive download for script-related extensions.

A payroll-themed `.cmd` file appeared on the victim user's Desktop shortly after the archive download completed.

At this point I treated the script as a candidate rather than assuming it was automatically responsible for the later activity.

The USN Journal showed a `FileCreate` event for the script and additional writes immediately afterward.

The NTFS entry number was then used to inspect the corresponding `$MFT` record.

---

### 4. Inspecting the Script's NTFS Metadata

The `$MFT` record confirmed the script filename and filesystem metadata.

The record also contained a named data stream:

```text
Zone.Identifier
```

The earlier USN activity had shown `NamedDataExtend` and `StreamChange` events associated with the same file. The MFT record provided additional context showing that the named stream was a `Zone.Identifier`.

This was consistent with Windows treating the file as originating from Internet-sourced content or inheriting Internet-zone information during extraction.

I did not treat the presence of Mark of the Web as proof of execution. It was supporting evidence about the file's origin and handling.

---

### 5. Correlating the Script with Execution

I next examined Windows Prefetch.

A `CMD.EXE` Prefetch artifact from the relevant incident window referenced the payroll-themed command script.

The same Prefetch artifact also referenced another native Windows executable that became important later in the investigation.

This provided stronger execution context than the USN Journal alone.

The distinction was important:

```text
USN Journal
→ proves filesystem activity

Prefetch
→ provides evidence of program execution and associated file references
```

Using both together provided a more defensible conclusion.

---

### 6. Identifying Native Windows Utility Abuse

Prefetch showed execution of a native Windows utility shortly after `cmd.exe`.

The utility had only a single recorded run in the relevant Prefetch artifact and its referenced files included a payroll-themed `.dat` file under both Windows Internet cache and temporary-file locations.

This was notable because the utility is legitimate Windows software, but its behavior in this context did not match the normal payroll workflow that initiated the incident.

Rather than treating the binary name itself as malicious, I evaluated:

* what executed before it;
* when it ran;
* which files it referenced;
* what network activity occurred around the same time; and
* what filesystem changes followed.

This helped identify abuse of a legitimate Windows binary rather than the introduction of a new third-party downloader.

---

### 7. Investigating the Transient File

The `.dat` file referenced by Prefetch became the next investigation pivot.

I searched the USN Journal for activity involving that filename.

The journal showed one copy appearing within Windows Internet cache and another under the user's local Temp directory.

The Temp copy showed a very short lifecycle:

```text
FileCreate
    ↓
DataExtend
    ↓
FileDelete
```

The file existed for only a fraction of a second.

This matched the description of a transient execution-related artifact much more closely than simply observing that the filename existed somewhere on disk.

The important lesson was that "transient" is a lifecycle characteristic. It needed to be demonstrated through creation and deletion records rather than inferred from the filename or location.

---

### 8. Correlating the External Retrieval

After identifying the transient file, I returned to the HTTP access logs and searched for requests containing the same resource name.

The logs contained successful requests for the corresponding resource on the external server.

Relevant fields included:

```text
method: GET
host: [external host omitted]
uri: /update/[resource omitted]
status: 200
```

Some requests also contained User-Agent values associated with Windows cryptographic and certificate functionality.

One server-side request specifically identified a CertUtil-related URL retrieval agent.

This provided a much stronger correlation between:

```text
command script
    ↓
cmd.exe
    ↓
native Windows utility
    ↓
external HTTP request
    ↓
temporary file activity
```

---

### 9. Resolving Timestamp Differences

One of the more difficult parts of the investigation involved timestamps.

Endpoint artifacts appeared to align around one host-side execution window, while the server-side access logs contained EPOCH timestamps that did not initially appear to match.

The challenge required using the server-side request record as the more reliable timestamp source for the successful external retrieval.

I converted the EPOCH value to UTC and used the server log associated specifically with the native utility's retrieval activity rather than selecting another request simply because its timestamp visually aligned with the endpoint artifacts.

This reinforced an important lesson:

> Temporal proximity is useful, but the most strongly identifying artifact should take priority when several similar events exist.

---

## Reconstructed Attack Chain

At a high level, the activity was reconstructed as:

```text
Payroll-themed phishing communication
        ↓
Outbound email link
        ↓
URL shortener
        ↓
External ZIP archive
        ↓
Archive downloaded to victim endpoint
        ↓
Archive extracted
        ↓
Payroll-themed command script created
        ↓
cmd.exe execution
        ↓
Native Windows utility execution
        ↓
External resource retrieved
        ↓
Internet cache artifact created
        ↓
Temporary .dat file created
        ↓
Temporary file deleted shortly afterward
```

Specific challenge-answer strings and indicators are intentionally omitted.

---

## Key Findings

### Finding 1 — Browser artifacts reconstructed the delivery chain

Browser download-chain records preserved the relationship between the original email link, shortened URL, final external archive, and local download.

This provided stronger evidence than simply finding isolated URLs in browser artifacts.

---

### Finding 2 — NTFS records preserved artifacts missing from the logical collection

Some user directories and files involved in the incident were not present as normal logical files in the triage collection.

The USN Journal and `$MFT` still preserved metadata showing that those files had existed and how they changed.

This demonstrated why absence from a logical directory listing does not automatically mean that a file never existed.

---

### Finding 3 — The extracted command script retained Internet-origin metadata

The command script's MFT record contained a `Zone.Identifier` alternate data stream.

This was consistent with Mark of the Web being associated with the extracted content.

---

### Finding 4 — Prefetch strengthened the execution correlation

Filesystem metadata established that the script existed, but Prefetch provided additional evidence connecting the command interpreter, the script, and the native Windows utility used later in the chain.

This prevented me from treating file creation as equivalent to execution.

---

### Finding 5 — A legitimate Windows binary was used during the retrieval stage

A native Windows utility executed immediately within the suspicious activity chain and referenced files associated with the retrieved external content.

Server-side HTTP logs further connected the utility with the external request.

This was an example of why native Windows tools need to be evaluated based on behavior and context rather than treated as automatically benign or malicious.

---

### Finding 6 — The retrieved file exhibited a transient lifecycle

The USN Journal recorded a temporary file being created, written, and deleted within a very short interval.

Correlating those records with Prefetch and HTTP activity showed that the file was part of the external retrieval sequence.

---

## Detection Opportunities

Based on this investigation, useful detection ideas would include:

### Suspicious Native Utility Network Activity

Alert when native Windows utilities that are not normally expected to retrieve Internet content establish outbound connections or access externally sourced files.

Detection should consider context such as:

* suspicious parent process;
* command interpreter ancestry;
* execution from a user-driven phishing chain;
* unusual destination;
* newly created files under `%TEMP%`; and
* proximity to archive extraction or script execution.

---

### Command Script Followed by Native Utility Execution

Monitor process relationships resembling:

```text
cmd.exe
    ↓
native Windows utility
```

especially when the activity begins with a newly created `.cmd` or `.bat` file in a user-writable location.

---

### Short-Lived Files in Temporary Locations

Files that are created, written, and deleted almost immediately may be worth investigating when they occur alongside:

* scripting activity;
* suspicious parent/child processes;
* outbound network activity; or
* execution of commonly abused native utilities.

A short lifecycle by itself is not malicious, so surrounding process and network context would be important for reducing false positives.

---

### Internet-Originated Script Execution

A command or script file carrying `Zone.Identifier` information may deserve additional review when it is followed closely by command interpreter activity and outbound network retrieval.

Mark of the Web alone should not be treated as malicious because it is expected on many legitimate Internet downloads.

---

## MITRE ATT&CK Mapping

The activity observed in the investigation is consistent with several ATT&CK concepts.

| Activity                                 | ATT&CK Mapping                                               |
| ---------------------------------------- | ------------------------------------------------------------ |
| Phishing link used as the initial lure   | Phishing: Spearphishing Link                                 |
| User interaction with downloaded content | User Execution                                               |
| Execution of a Windows command script    | Command and Scripting Interpreter: Windows Command Shell     |
| Retrieval of additional external content | Ingress Tool Transfer                                        |
| Abuse of a legitimate Windows binary     | System Binary Proxy Execution / native utility abuse context |

The mappings above are intended to describe the observed behavior at a high level rather than claim every possible ATT&CK technique associated with the tools involved.

---

## Lessons Learned

### File presence is not execution proof

One of the main lessons from this investigation was learning to distinguish between:

```text
file existed
```

and:

```text
file executed
```

The USN Journal was excellent for discovering and timing filesystem activity, but Prefetch provided additional execution context.

---

### Candidate indicators need correlation

A filename that looks suspicious is only a starting point.

A more reliable progression was:

```text
candidate artifact
    ↓
filesystem evidence
    ↓
execution evidence
    ↓
network evidence
    ↓
corroborated finding
```

This approach was useful several times during the investigation.

---

### NTFS metadata can preserve evidence after the logical file is unavailable

The logical triage directory did not contain every file referenced by the forensic metadata.

USN and MFT analysis still provided information about files that were no longer available directly within the collected directory structure.

---

### Native Windows tools need behavioral context

Before this investigation I was not familiar with the investigated native utility as something that could be abused for external content retrieval.

The useful lesson was not simply memorizing another suspicious executable name.

Instead, I learned to ask:

* Why is this Windows utility running here?
* What launched it?
* What happened immediately before and after?
* What files did it touch?
* Did it generate network activity?
* Does that behavior make sense for the user's expected activity?

That approach is more useful than assuming a Windows binary is malicious based only on its name.

---

### Different evidence sources may use different timestamp formats

The investigation involved normal Windows timestamps as well as EPOCH timestamps in HTTP logs.

Converting server-side timestamps to UTC and comparing them with endpoint activity helped reinforce the importance of understanding both the timestamp format and the source generating it.

The server-side record ultimately provided the stronger timestamp for the external retrieval event.

---

## Tools and Commands Practiced

### PowerShell

PowerShell was used to:

* recursively inspect the triage collection;
* filter artifacts by filename and extension;
* import parsed CSV output;
* filter USN Journal records;
* sort events chronologically;
* search HTTP logs;
* and convert EPOCH timestamps.

Example structure used during USN analysis:

```powershell
$usn = Import-Csv ".\Parsed\USN-Journal.csv"

$usn |
    Where-Object {
        $_.Name -like '*keyword*'
    } |
    Sort-Object UpdateTimestamp |
    Select-Object Name, ParentPath, UpdateTimestamp, UpdateReasons
```

---

### MFTECmd

MFTECmd was used to parse the NTFS USN Journal and inspect individual MFT records.

This provided experience working with:

* NTFS entry numbers;
* filesystem paths;
* update reasons;
* `$DATA` attributes;
* alternate data streams; and
* NTFS timestamps.

---

### PECmd

PECmd was used to parse Windows Prefetch artifacts.

The Prefetch data helped identify:

* executable run times;
* run counts;
* referenced directories; and
* referenced files related to the execution chain.

---

### DB Browser for SQLite

DB Browser for SQLite was used to inspect Chromium browser databases, particularly download and URL-chain information.

This was useful for reconstructing the redirects associated with the initial archive download.

---

## Final Assessment

The investigation showed a phishing-driven execution chain in which a payroll-themed archive led to command-script execution and the use of a legitimate Windows utility to retrieve additional external content.

The strongest conclusions came from combining multiple artifact types rather than relying on a single source.

Browser artifacts established the delivery path, NTFS metadata reconstructed file creation and deletion, Prefetch added execution context, and server-side HTTP logs confirmed the external retrieval.

This investigation gave me additional practice in Windows filesystem forensics, execution artifact analysis, timeline reconstruction, and evidence correlation across endpoint and network-side sources.

