# Introduction

ShiftLeft Scan is a free [open-source](https://github.com/ShiftLeftSecurity/sast-scan) security tool for modern DevOps teams. With an integrated multi-scanner based design, ShiftLeft Scan can detect various kinds of security flaws in your application and infrastructure code in a single fast scan. The kind of flaws detected are:

* [x] Credentials Scanning to detect accidental secret leaks
* [x] Static Analysis Security Testing (SAST) for a range of languages and frameworks
* [x] Open-source dependencies audit
* [x] Licence violation checks

!!! Summary
    Scan supports a range of integration options: from scanning the code on your IDE to scanning every build and pull-request in the CI/CD pipelines.

## Sample invocation

Easy one-liner command below:

```bash
sh <(curl https://slscan.sh)
```

The above command simply invokes the below docker run command.

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan
```

![Java Scan](getting-started/images/scan-java.gif)

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
| Salesforce Apex     | ✓ | ✓ | ✕ | ✕ | ✓ |
| Ansible     | ✓ | 🚧 | ✕ | ✕ | ✕ |
| AWS CloudFormation     | ✓ | ✓ | ✕ | ✕ | ✕ |
| Bash     | ✓ | ✓ | ✕ | ✕ | ✓ |
| Go     | ✓ | ✓ | ✓ | ✓ | ✓ |
| Java     | ✓ | ✓ | ✓ | ✓ | ✓ |
| JSP     | ✓ | ✓ | ✓ | ✓ | ✓ |
| Node.js     | ✓ | 🚧 | ✓ | ✓ | ✓ |
| PL/SQL     | ✓ | ✓ | ✕ | ✕ | ✓ |
| Python     | ✓ | ✓ | ✓ | ✓ | ✓ |
| Rust     | ✓ | ✕ | ✓ | ✕ | ✕ |
| Kubernetes     | ✓ | ✓ | ✕ | ✕ | ✕ |
| Terraform     | ✓ | ✓ | ✕ | ✕ | ✓ |
| Salesforce Visual Force     | ✓ | ✓ | ✕ | ✕ | ✓ |
| Apache Velocity     | ✓ | ✓ | ✕ | ✕ | ✓ |
| Kotlin     | ✓ | 🚧 | ✕ | ✕ | ✕ |
| Yaml     | ✓ | 🚧 | ✕ | ✕ | ✕ |

🚧 - Work-in-progress feature

## Start with your use case

=== "Secure development"
    - Read more about [secure development](secure-development/README.md) and best practices with scan for a range of languages
=== "Scan GitHub"
    - Use scan with [GitHub code scanning](integrations/code-scan.md)
=== "Integrate with CI/CD"
    - Explore the available [CI/CD integrations](integrations/README.md)
=== "Integrate with other tools"
    - Read more about the [SARIF format](integrations/sarif.md) used by scan for integration with any existing tools such as Semmle
