# Introduction

ShiftLeft Scan is a free [open-source](https://github.com/ShiftLeftSecurity/sast-scan) security tool for modern DevOps teams. With an integrated multi-scanner based design, ShiftLeft Scan can detect various kinds of security flaws in your application and infrastructure code in a single fast scan. The kind of flaws detected are:

* [x] Credentials Scanning to detect accidental secret leaks
* [x] Static Analysis Security Testing (SAST) for a range of languages and frameworks
* [x] Open-source dependencies audit
* [x] Licence violation checks

!!! Summary
    Scan supports a range of integration options: from scanning the code on your IDE to scanning every build and pull-request in the CI/CD pipelines.

## Supported Languages & Frameworks

Full list of supported languages is as follows:

- Salesforce Apex
- Bash
- Go
- Java
- JSP
- Node.js
- Oracle PL/SQL
- Python
- Rust (Dependency and Licence scan alone)
- Terraform
- Salesforce Visual Force
- Apache Velocity

In addition, support for Infrastructure as Code (IaC) frameworks such as Ansible, AWS CloudFormation, Terraform, Kubernetes is also available. Scanning for more additional languages is in the works.

## Language & supported scan types

| Language | Credential Scan | SAST | Dependency Scan | License Audit | Build Breaker |
|----------|---------------------|------|-----------------|---------------|---------------|
| Salesforce Apex     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-check: |
| Ansible     | :octicons-check: | :octicons-beaker: | :octicons-x: | :octicons-x: | :octicons-x: |
| AWS CloudFormation     | :octicons-check: | :octicons-beaker: | :octicons-x: | :octicons-x: | :octicons-x: |
| Bash     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-check: |
| Go     | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-check: |
| Java     | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-check: |
| JSP     | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-check: |
| Node.js     | :octicons-check: | :octicons-beaker: | :octicons-check: | :octicons-check: | :octicons-check: |
| PL/SQL     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-check: |
| Python     | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-check: | :octicons-check: |
| Rust     | :octicons-check: | :octicons-x: | :octicons-check: | :octicons-x: | :octicons-x: |
| Kubernetes     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-x: |
| Terraform     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-check: |
| Salesforce Visual Force     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-check: |
| Apache Velocity     | :octicons-check: | :octicons-check: | :octicons-x: | :octicons-x: | :octicons-check: |
| Kotlin     | :octicons-check: | :octicons-beaker: | :octicons-x: | :octicons-x: | :octicons-x: |
| Yaml     | :octicons-check: | :octicons-beaker: | :octicons-x: | :octicons-x: | :octicons-x: |

:octicons-beaker: - Experimental feature

## Start with your use case

=== "Secure development"
    - Read more about [secure development](secure-development/README.md) and best practices with scan for a range of languages
=== "Scan GitHub"
    - Use scan with [GitHub code scanning](integrations/code-scan.md)
=== "Integrate with CI/CD"
    - Explore the available [CI/CD integrations](integrations/README.md)
=== "Integrate with other tools"
    - Read more about the [SARIF format](integrations/sarif.md) used by scan for integration with any existing tools such as Semmle
