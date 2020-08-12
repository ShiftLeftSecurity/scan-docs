# Introduction

ShiftLeft Scan is a free [open-source](https://github.com/ShiftLeftSecurity/sast-scan) security tool for modern DevOps teams. With an integrated multi-scanner based design, ShiftLeft Scan can detect various kinds of security flaws in your application and infrastructure code in a single fast scan without the need for any _remote server_. The kind of flaws detected are:

* [x] Credentials Scanning to detect accidental secret leaks
* [x] Static Analysis Security Testing (SAST) for a range of languages and frameworks
* [x] Open-source dependencies audit
* [x] Licence violation checks

!!! Workflow
    Scan is purpose built for DevSecOps workflow [integrations](integrations) with nifty features such as automatic build breaker, Pull Request summary comments, GitHub [Code scanning](integrations/code-scan.md) and [Bitbucket](integrations/bitbucket.md) Code Insights support and so on.

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

Scan is also available as an AppImage. Please download the latest version from GitHub [releases](https://github.com/ShiftLeftSecurity/sast-scan/releases) or use the one-liner command below.

```bash
sh <(curl https://slscan.sh/install)
```

Expanded version of the one-liner command.

```bash
wget https://github.com/ShiftLeftSecurity/sast-scan/releases/download/v1.9.9/scan
chmod +x scan
./scan -t nodejs
```

## Supported Languages & Frameworks

Full list of supported languages is as follows:

| Language | Scan Type (--type) | Credential Scan | SAST | Dependency Scan | License Audit | Build Breaker |
|----------|-----------|---------------------|------|-----------------|---------------|---------------|
| Salesforce Apex     | apex | ✓ | ✓ | | | ✓ |
| Ansible     | ansible | ✓ | 🚧 | | | |
| AWS CloudFormation / CDK     | aws | ✓ | ✓ | | | ✓ |
| Azure Resource Manager Templates     | arm | ✓ | ✓ | | | ✓ |
| Bash     | bash | ✓ | ✓ | | | ✓ |
| Go     | go | ✓ | ✓ | ✓ | ✓ | ✓ |
| Java     | java | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kotlin    | kotlin | ✓ | ✓ | ✓ | ✓ | ✓ |
| Scala    | scala | ✓ | ✓ |  |  | ✓ |
| Groovy    | groovy | ✓ | ✓ | ✓ | ✓ | ✓ |
| JSP     | jsp | ✓ | ✓ | ✓ | ✓ | ✓ |
| Node.js     | nodejs | ✓ | 🚧 | ✓ | ✓ | ✓ |
| PL/SQL     | plsql | ✓ | ✓ | | | ✓ |
| Php     | php | ✓ | ✓ | ✓ | ✓ | ✓ |
| Python     | python | ✓ | ✓ | ✓ | ✓ | ✓ |
| Ruby     | ruby | ✓ | | ✓ | ✓ | |
| Rust     | rust | ✓ | | ✓ | ✓ | |
| Kubernetes     | kubernetes | ✓ | ✓ | | | ✓ |
| Serverless     | serverless | ✓ | ✓ | | | ✓ |
| Terraform     | terraform | ✓ | ✓ | | | ✓ |
| Salesforce Visual Force    | vf | ✓ | ✓ | | | ✓ |
| Apache Velocity    | vm | ✓ | ✓ | | | ✓ |
| Yaml     | yaml | ✓ | 🚧 | | | |

🚧 - Work-in-progress feature

To scan AWS CDK codebase, export to cloudformation and then scan using `aws` type.

## Start with your use case

=== "Integrate with CI/CD"
    - Explore the available [CI/CD integrations](integrations/README.md)
=== "Scan GitHub"
    - Use scan with [GitHub code scanning](integrations/code-scan.md)
=== "Secure development"
    - Read more about [secure development](secure-development/README.md) and best practices with scan for a range of languages
=== "Advanced use cases"
    - Read more about the [SARIF format](integrations/sarif.md) used by scan for integration with any SARIF compliant SAST tool
    - Learn about the [Software Bill-of-Materials](integrations/sbom.md) report produced by scan
    - Learn about rolling out a [telemetry service](integrations/telemetry.md) to aggregate and audit scan invocations

## Support

Developers behind scan are available on a dedicated [discord channel](https://discord.gg/gC62PzS) for questions and support. For defects, raising an issue on [GitHub](https://github.com/ShiftLeftSecurity/sast-scan/issues) is best.
