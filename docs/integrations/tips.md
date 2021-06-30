# Tips and tricks

This page captures advanced customization and tweaks supported by scan.

## Automatic build

Scan can attempt to build certain project types such as Java, go, node.js, rust and csharp using the bundled runtimes. To enable auto build simply pass `--build` argument or set the environment variable `SCAN_AUTO_BUILD` to a non-empty value.

## Workspace path prefix

scan tool is typically invoked using the docker container image with volume mounts. Due to this behaviour, the source path the tools would see would be different to the source path in the developer laptop or in the CI environment.

To override the prefix, simply pass the environment variable `WORKSPACE` with the path that should get prefixed in the reports.

```bash
export WORKSPACE="/home/shiftleft/src"

# To specify url
export WORKSPACE="https://github.com/ShiftLeftSecurity/sast-scan/blob/master"
```

## Config file

scan can load configurations automatically from `.sastscanrc` in the repo root directory. This file is a json file containing the keys from [config.py](https://github.com/ShiftLeftSecurity/sast-scan/blob/master/lib/config.py).

Below is an example for overriding the default build breaker logic.

```json
{
  "build_break_rules": {
    "default": {"max_critical": 2, "max_high": 5, "max_medium": 15}
  }
}
```

Any number of vulnerabilities over and above this limit would cause the build to fail. It is also possible to specify a tool specific rule.

```json
{
  "build_break_rules": {
    "default": {"max_critical": 2, "max_high": 5, "max_medium": 15},
    "Security audit for PHP": {"max_critical": 2, "max_high": 50, "max_medium": 500}
  }
}
```

With this rule, the tool `Security audit for PHP` would mark the build as success as shown.

```bash
SAST Scan Summary
╔═════════════════════════════════╤══════════╤══════╤════════╤═════╤════════╗
║ Tool                            │ Critical │ High │ Medium │ Low │ Status ║
╟─────────────────────────────────┼──────────┼──────┼────────┼─────┼────────╢
║ Security audit for PHP          │        0 │    0 │    309 │   0 │   ✅   ║
║ Security taint analysis for PHP │      130 │    0 │      0 │   0 │   ❌   ║
╚═════════════════════════════════╧══════════╧══════╧════════╧═════╧════════╝
```

With a local config you can override the scan type and even configure the command line args for the tools as shown.
In the following table, you can see which are the keys to use in order to configure its `build_break_rules`:

| Tool | Key |
|------|-----|
| nodejsscan | Static Security code scan |
| njsscan | Static Security code scan |
| findsecbugs | Class File Analyzer |
| pmd | Source Code Analyzer |
| /opt/pmd-bin/bin/run.sh | Source Code Analyzer |
| gitleaks | Secrets Audit |
| gosec | Go Security Audit |
| tfsec | Terraform Static Analysis |
| lint-tf | Terraform Static Analysis |
| shellcheck | Shell Script Analysis |
| bandit | Security Audit for Python |
| checkov | Security Audit for Infrastructure |
| source-aws | Security Audit for AWS |
| source-arm | Security Audit for Azure Resource Manager |
| source-k8s | Kubernetes Security Audit |
| source-kt | Kotlin Static Analysis |
| audit-kt | Kotlin Security Audit |
| audit-groovy | Groovy Security Audit |
| audit-scala | Scala Security Audit |
| detekt | Kotlin Static Analysis |
| source-tf | Terraform Security Audit |
| source-yaml | Security Audit for IaC |
| staticcheck | Go Static Analysis |
| source | Source Aode Analyzer |
| source-java | Java Source Analyzer |
| source-python | Python Source Analyzer |
| source-php | PHP Source Analyzer |
| phpstan | PHP Source Analyzer |
| audit-python | Python Security Audit |
| audit-php | PHP Security Audit |
| taint-php | PHP Security Analysis |
| taint-python | Python Security Analysis |
| psalm | PHP Security Audit |
| /opt/phpsast/vendor/bin/psalm | PHP Security Analysis |
| source-js | JavaScript Source Analyzer |
| source-go | Go Source Analyzer |
| source-vm | Apache Velocity Source Analyzer |
| source-vf | VisualForce Source Analyzer |
| source-sql | SQL Source Analyzer |
| source-jsp | JSP Source Analyzer |
| source-serverless | Serverless Security Audit |
| audit-jsp | JSP Security Audit |
| source-apex | Apex Source Analyzer |
| binary | Binary byte-code Analyzer |
| class | Class File Analyzer |
| jar | Jar File Analyzer |
| cpg | ShiftLeft NextGen Analyzer |
| inspect | ShiftLeft NextGen Analyzer |
| ng-sast | ShiftLeft NextGen Analyzer |
| source-ruby | Ruby Source Analyzer |

!!! Note
    It is currently not possible to include dependency and license scan result as a build breaker rule. This [issue](https://github.com/ShiftLeftSecurity/sast-scan/issues/136) tracks this feature request.


## Use CI build reference as runGuid

By setting the environment variable `SCAN_ID` you can re-use the CI build reference as the run guid for the reports. This is useful to reverse lookup the pipeline result based on the scan result.

## Creating bash alias

Add the below alias to your .bashrc or .zshrc file to simplify the scan command for terminal invocations.

```bash
scan() {
    docker run --rm -e "WORKSPACE=$(pwd)" -e GITHUB_TOKEN -v "$(pwd):/app" shiftleft/scan scan $*
}
```

To perform scan with this alias, simply use the word scan

```bash
scan --type java
```

This approach seems to work with Linux, Mac and WSL 1 and 2 for Windows.

## Run as normal user

Pass `--user uid:gid` to the docker run commands to run scan as a normal user. If you get any directory creation errors then create the reports and VDB_HOME directories upfront, chown and then run scan.

```bash
mkdir -p reports,vdb
chown -R 1000:1000 reports,vdb
docker run --user 1000:1000 ...
```

## Run without network connectivity

Pass `--network none` to the docker run command to perform security scan without any external connectivity.

```bash
docker run --network none ...
```

Automatic build and depscan will not work without connectivity. However, by caching the vulnerability database in a directory defined by the environment variable `VDB_HOME` and by building the projects upfront it is possible to run security scan without any external connectivity.

## Seccomp profile

Scan supports invocation with a seccomp profile which can be downloaded from [here](https://github.com/ShiftLeftSecurity/sast-scan/blob/master/contrib/seccomp.json)

```bash
# Copy seccomp.json from https://github.com/ShiftLeftSecurity/sast-scan/blob/master/contrib/seccomp.json
podman run --security-opt seccomp=/home/guest/sast-scan/contrib/seccomp.json -e "WORKSPACE=$(pwd)" -v "$(pwd):/app" shiftleft/scan scan
```

## Troubleshooting

Scan by default suppresses all errors and messages from the tools as a [philosophy](../getting-started/zen-of-scan.md). To debug issues, especially when 0 results are reported by all tools, simply pass the environment variable `SCAN_DEBUG_MODE=debug` as shown.

```
-e SCAN_DEBUG_MODE=debug
```
