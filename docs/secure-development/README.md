# Introduction

Secure development practices include performing automated security scans using tools such as Scan sooner and at every stage during a Software Development Lifecycle (SDLC).

## Integrating scan in your SDLC

![SDLC](images/SDLC.jpg)

### Define

Define the security requirements along with the functional and non-functional requirements for the given feature or enhancement or even for major bug fixes. If you team is new to DevSecOps, then [this post](https://blog.shiftleft.io/dev-sec-ops-devsecops-5d05e3516e00) might help in deciding the ideal anchor points for automated security reviews.

### Design

This is the phase where the developer/team thinks and researches about the upcoming work. They could be investigating libraries and packages, or the logic required to satisfy the requirements. Scan could help them from this process onwards — by checking the library for [known vulnerabilities](../getting-started/README.md) and by helping assess the business logic for known security flaws via the [VS code extension](../integrations/vscode.md).

### Develop

Use Scan [VS code extension](../integrations/vscode.md) to continuously assess and test the source code as you develop. Scan can also look for possible credential leaks and help you prevent the leaks before they get committed to the repository.

### Deploy

Scan can be embedded into this process by scanning the configuration and automation scripts for credential leaks, improper configuration of cloud resources (public s3 buckets or firewall), and security best practices in general. Ansible, AWS cloudformation and Terraform are natively supported by scan.

### Maintain

The [SARIF](../integrations/sarif.md) and HTML reports produced by scan can be included as part of the development or release tickets for tracking the vulnerabilities and for auditing purposes. Any maintenance script can also stored in a repository and security checked with scan.

## Language specific best practices

Check out the language specific best practices and remediation techniques listed on the side bar. We have guides for languages such as [Python](python.md), [Go](go.md), [JavaScript](javascript.md).
