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
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan --build
```

![Java Scan](getting-started/images/scan-java.gif)

## Supported Languages & Frameworks

Full list of supported languages is as follows:

| Language | Scan Type (--type) | Credential Scan | SAST | Dependency Scan | License Audit | Build Breaker |
|----------|-----------|---------------------|------|-----------------|---------------|---------------|
| Salesforce Apex     | apex | ✓ | ✓ | | | ✓ |
| Ansible     | ansible | ✓ | 🚧 | | | |
| AWS CloudFormation     | aws | ✓ | ✓ | | | |
| Bash     | bash | ✓ | ✓ | | | ✓ |
| Go     | go | ✓ | ✓ | ✓ | ✓ | ✓ |
| Java     | java | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kotlin    | kotlin | ✓ | ✓ | ✓ | ✓ | ✓ |
| JSP     | jsp | ✓ | ✓ | ✓ | ✓ | ✓ |
| Node.js     | nodejs | ✓ | 🚧 | ✓ | ✓ | ✓ |
| PL/SQL     | plsql | ✓ | ✓ | | | ✓ |
| Php     | php | ✓ | ✓ | ✓ | ✓ | ✓ |
| Python     | python | ✓ | ✓ | ✓ | ✓ | ✓ |
| Rust     | rust | ✓ | | ✓ | | |
| Kubernetes     | kubernetes | ✓ | ✓ | | | |
| Terraform     | terraform | ✓ | ✓ | | | ✓ |
| Salesforce Visual Force    | vf | ✓ | ✓ | | | ✓ |
| Apache Velocity    | vm | ✓ | ✓ | | | ✓ |
| Yaml     | yaml | ✓ | 🚧 | | | |

🚧 - Work-in-progress feature

## Start with your use case

=== "Secure development"
    - Read more about [secure development](secure-development/README.md) and best practices with scan for a range of languages
=== "Scan GitHub"
    - Use scan with [GitHub code scanning](integrations/code-scan.md)
=== "Integrate with CI/CD"
    - Explore the available [CI/CD integrations](integrations/README.md)
=== "Advanced use cases"
    - Read more about the [SARIF format](integrations/sarif.md) used by scan for integration with any SARIF compliant SAST tool
    - Learn about the [Software Bill-of-Materials](integrations/sbom.md) report produced by scan
    - Learn about rolling out a [telemetry service](integrations/telemetry.md) to aggregate and audit scan invocations
