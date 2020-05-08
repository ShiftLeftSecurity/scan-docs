# Introduction

ShiftLeft Scan is a free [open-source](https://github.com/ShiftLeftSecurity/sast-scan) security tool for modern DevOps teams. With an integrated multi-scanner based design, ShiftLeft Scan can detect various kinds of security flaws in your application and infrastructure code in a single fast scan. The kind of flaws detected are:

* [x] Credentials Scanning to detect accidental secret leaks
* [x] Static Analysis Security Testing (SAST) for a range of languages and frameworks
* [x] Open-source dependencies audit
* [x] Licence violation checks

!!! summary
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

## Start with your use case

=== "Secure development"
    - Install Visual Studio Code [extension](integrations/vscode.md)
=== "Scan GitHub repository"
    - Use scan with [GitHub code scanning](integrations/code-scan.md)
=== "Scan during CI/CD"
    - Explore the available [CI/CD integrations](integrations/README.md)
