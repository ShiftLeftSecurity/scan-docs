# Scan SARIF format

This document describes the output SARIF format emitted by `scan` tool for integration purposes.

## SARIF specification

sast-tool implements version 2.1.0 specification which can be found [here](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012479). Every release of sast-tool is carefully tested to remain compliant and produce valid SARIF files. The [online validator](https://sarifweb.azurewebsites.net/Validation) can be used to validate the [sample files](https://github.com/ShiftLeftSecurity/scan/blob/master/test/data/findsecbugs-report.sarif).

## SARIF components

### sarifLog

- version: 2.1.0
- \$schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json
- inlineExternalProperties:
  - guid - UUID representing each report from the tool
  - runGuid - UUID representing an invocation of scan which can produce multiple reports. This can be specified by setting the environment variable `SCAN_ID`
- runs: Array with a single run object representing a single run of a tool. This might however change in the future to represent tools that perform multiple scans per invocation.

### run

- tool:
  - driver: This section would describe the tool used to perform the scan along with the rules applied. Eg: A scan for go would lead to the below section

```json
"tool": {
    "driver": {
        "name": "Security audit for Go",
        "rules": [
        {
            "id": "CWE-22",
            "help": {
            "text": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.\nMany file operations are intended to take place within a restricted directory. By using special elements such as .. and / separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the ../ sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as /usr/local/bin, which may also be useful in accessing unexpected files. This is referred to as absolute path traversal. In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to widen the scope of attack. For example, the software may add .txt to any pathname, thus limiting the attacker to text files, but a null injection may effectively remove this restriction.",
            "markdown": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.\nMany file operations are intended to take place within a restricted directory. By using special elements such as .. and / separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the ../ sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as /usr/local/bin, which may also be useful in accessing unexpected files. This is referred to as absolute path traversal. In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to widen the scope of attack. For example, the software may add .txt to any pathname, thus limiting the attacker to text files, but a null injection may effectively remove this restriction."
            },
            "name": "",
            "properties": {
            "tags": [
                "Scan"
            ],
            "precision": "very-high"
            },
            "defaultConfiguration": {
            "level": "warning"
            },
            "fullDescription": {
            "text": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."
            },
            "helpUri": "https://cwe.mitre.org/data/definitions/22.html",
            "shortDescription": {
            "text": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')."
            }
        },
```

- conversion: This section would contain information on how scan utilized the underlying tool to perform the report conversion to SARIF format.
- invocations: This section would contain useful information such as:
  - endTimeUtc: Scan end time
  - workingDirectory: Working directory used for the scan
- properties:
  - metrics: This section contains the scan summary such as total issues found as well as the number of critical, high, medium and low issues.

```json
"properties": {
  "metrics": {
    "total": 35,
    "critical": 0,
    "high": 5,
    "medium": 30,
    "low": 0
  }
}
```

- results: An array of result object representing the findings

### result

- message: Detailed message from the tool representing the finding in text and also in markdown format if available.
- level: string representing the type of finding - can be error, warning, note
- locations: An array of information representing the source code, line numbers, filename (`artifactLocation`) along with the code snippet highlighting the issue. artifactLocation would start with either https:// or file:// protocol depending on the `WORKSPACE` environment variable used
- properties:
    - issue_confidence: UPPER case flag indicating the confidence level of the tool for the particular result. Valid values are: HIGH, MEDIUM, LOW
    - issue_severity: UPPER case flag indicating the severity level of the particular result. Valid values are: HIGH, MEDIUM, LOW
- baselineState: Indicates if the defect is new or recurring. Currently defaults to new for all reports
- partialFingerprints: Contains the following fingerprints
    - scanPrimaryLocationHash: Hash of the code snippet pointing to the vulnerability. Usually the exact location (All languages) or the source (Python and PHP)
    - scanTagsHash: Hash of the source and sink tags (Python only)
    - scanFileHash: Hash of the file location (All languages)
- ruleId: ID of the rule used. This will be the present in the list of rules mentioned in the tool section
- ruleIndex: Index of the rule in the tool section for faster lookups

Example of a result is shown below:

```json
{
    "message": {
        "markdown": "",
        "text": "Blacklisted import crypto/md5: weak cryptographic primitive."
    },
    "locations": [
    {
        "physicalLocation": {
            "region": {
                "snippet": {
                "text": "\t\"crypto/md5\"\n"
                },
                "startLine": 8
            },
            "artifactLocation": {
                "uri": "file:///Users/prabhu/go/opa/topdown/crypto.go"
            },
            "contextRegion": {
                "snippet": {
                "text": "import (\n\t\"crypto/md5\"\n"
                },
                "endLine": 8,
                "startLine": 7
            }
        }
    }
    ],
    "properties": {
        "issue_confidence": "HIGH",
        "issue_severity": "MEDIUM"
    },
    "baselineState": "new",
    "partialFingerprints": {
        "scanPrimaryLocationHash": "f35827a889ebadc4",
        "scanTagsHash": "e037139a5cd2951e",
        "scanFileHash": "8aca4cdbb13ad2dc"
    },
    "ruleId": "CWE-327",
    "ruleIndex": 2
}
```
