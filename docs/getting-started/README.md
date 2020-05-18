# Getting Started

ShiftLeft Scan is distributed as a container [image](https://hub.docker.com/r/shiftleft/sast-scan) and hence it is easy to install, setup in the CI or locally, and then to run it.

## Scanning the Application Locally

### Pre-requisites

- Docker [desktop](https://www.docker.com/products/docker-desktop) in case of Windows and Mac
- For linux [install](https://docs.docker.com/engine/install/) and then complete these [post-install](https://docs.docker.com/engine/install/linux-postinstall/) steps.

### Your first scan

=== "Linux and Mac"
    Invoking the `scan` command *detects* the language automatically and proceeds with a scan

    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan
    ```

    For project types such as Java, go compile the projects prior to scanning. Or pass `--build` to attempt automatic build.

    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --build
    ```

    For scanning a specific language project, use the `--type` option. For example, for scanning a python project,

    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --src /app --type python
    ```

=== "Windows"
    On Windows use `%cd%` instead of \$PWD to run the scan with Command prompt

    ```cmd
    docker run --rm -e "WORKSPACE=%cd%" -v "%cd%:/app:cached" shiftleft/sast-scan scan --src /app --type python
    ```

    powershell and powershell core

    ```powershell
    docker run --rm -e "WORKSPACE=$(pwd)" -e "GITHUB_TOKEN=$env:GITHUB_TOKEN" -v "$(pwd):/app:cached" shiftleft/scan scan
    ```

    WSL bash

    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -e "GITHUB_TOKEN=${GITHUB_TOKEN}" -v "$PWD:/app:cached" shiftleft/scan scan
    ```

    git-bash

    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -e "GITHUB_TOKEN=${GITHUB_TOKEN}" -v "/$PWD:/app:cached" shiftleft/scan scan
    ```

    Don't forget the slash (/) before \$PWD for git-bash!

To scan multiple projects, separate the types with a comma. Here reports will be put in the directory specified by `--out_dir`

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan --src /app --type credscan,nodejs,python,yaml --out_dir /app/reports
```

### Scanning Java Projects

> For Java and JVM projects, it is important to *compile* the projects before invoking sast-scan in the dev and CI workflow.

```bash
docker run --rm -e "WORKSPACE=${PWD}" -v <source path>:/app shiftleft/sast-scan scan --src /app --type java
```

### Language specific scans

=== "Credential scanning"
    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --src /app --type credscan
    ```

=== "Python"
    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --src /app --type python
    ```

=== "Dependency scanning"
    To perform dependency scanning, create a personal access token with `read:packages` scope from settings -> developer settings on github.
    ![Reports](../integrations/img/github_token.png)
    Then pass this value as `GITHUB_TOKEN` as shown.
    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -e "GITHUB_TOKEN=${GITHUB_TOKEN}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --src /app --type depscan
    ```

=== "Node.js"
    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --src /app --type nodejs
    ```

=== "go"
    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app:cached" shiftleft/sast-scan scan --src /app --type go
    ```

Refer to the [readme](https://github.com/ShiftLeftSecurity/sast-scan#bundled-tools) for a complete list of all scan types.

### Sample invocation

```
$ docker run --rm -e "WORKSPACE=${PWD}" -v $PWD:/app shiftleft/sast-scan scan


███████╗██╗  ██╗██╗███████╗████████╗██╗     ███████╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██║  ██║██║██╔════╝╚══██╔══╝██║     ██╔════╝██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗███████║██║█████╗     ██║   ██║     █████╗  █████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══██║██║██╔══╝     ██║   ██║     ██╔══╝  ██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║  ██║██║██║        ██║   ███████╗███████╗██║        ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝╚══════╝╚═╝        ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

INFO [2020-04-02 12:36:39,608] Scanning /app using scan plugins ['credscan', 'java', 'bash', 'depscan']
INFO [2020-04-02 12:36:39,609] ================================================================================
WARN[2020-04-02T12:36:39Z] Exceeded depth limit (2)
INFO[2020-04-02T12:36:39Z] no leaks found, skipping writing report
INFO[2020-04-02T12:36:39Z] No leaks detected. 2 commits audited in 8 milliseconds 936 microseconds
INFO [2020-04-02 12:36:39,625] ================================================================================
INFO [2020-04-02 12:36:44,402] ================================================================================
INFO [2020-04-02 12:36:46,198] ================================================================================
INFO [2020-04-02 12:36:46,246] ================================================================================
INFO [2020-04-02 12:36:46,403] ================================================================================
INFO [2020-04-02 12:36:46,403] ⚡︎ Executing "cdxgen -r -t java -o /app/reports/bom-java.xml /app"

===License scan findings===

+--------------------------------+-----------+--------------+--------------------------------------------------+
| Package                        | Version   | License Id   | License conditions                               |
+================================+===========+==============+==================================================+
| ch.qos.logback:logback-classic | 1.1.9     | EPL-1.0      | disclose-source, include-copyright, same-license |
+--------------------------------+-----------+--------------+--------------------------------------------------+
| ch.qos.logback:logback-core    | 1.1.9     | EPL-1.0      | disclose-source, include-copyright, same-license |
+--------------------------------+-----------+--------------+--------------------------------------------------+
| org.aspectj:aspectjweaver      | 1.8.9     | EPL-1.0      | disclose-source, include-copyright, same-license |
+--------------------------------+-----------+--------------+--------------------------------------------------+
INFO [2020-04-02 12:37:33,451] To use GitHub advisory source please set the environment variable GITHUB_TOKEN!
INFO [2020-04-02 12:38:19,811] Performing regular scan for /app using plugin java
INFO [2020-04-02 12:38:19,812] Scanning 67 oss dependencies for issues
INFO [2020-04-02 12:38:29,415] No oss vulnerabilities detected ✅


tool         description                             critical    high    medium    low  status
-----------  ------------------------------------  ----------  ------  --------  -----  --------
findsecbugs  Security audit by Find Security Bugs           8      16         0      0  ❌
shellcheck   Shell script analysis by shellcheck            0       0         0      0  ✅
pmd          Static code analysis by PMD                    0       0        19     35  ❌
```

## Command-line arguments

```bash
usage: scan [-h] [-i SRC_DIR] [-o REPORTS_DIR] [-t SCAN_TYPE] [-c] [--build]
            [--no-error] [-m SCAN_MODE]

Wrapper for various static analysis tools

optional arguments:
  -h, --help            show this help message and exit
  -i SRC_DIR, --src SRC_DIR
                        Source directory
  -o REPORTS_DIR, --out_dir REPORTS_DIR
                        Reports directory
  -t SCAN_TYPE, --type SCAN_TYPE
                        Override project type if auto-detection is incorrect.
                        Comma separated values for multiple types. Eg:
                        python,bash,credscan
  -c, --convert         Convert results to sarif json format
  --build               Attempt to automatically build the project for
                        supported types
  --no-error            Continue on error to prevent build from breaking
  -m SCAN_MODE, --mode SCAN_MODE
                        Scan mode to use ci, ide, pr, release, deploy
```

All the arguments are _optional_ for scan.

## Environment variables

Scan use a number of environment variables for configuration and cutomizing the default behaviour.

| Variable        | Purpose                                                                                                                                |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| WORKSPACE       | URL or the path to use for all references to the source code. Use blank to use relative path or in case of GitHub code scanning        |
| SCAN_ID         | Custom id to use for the scan run. Set this to match your CI job id or any other id to simplify integration                            |
| SCAN_AUTO_BUILD | Enables automatic build using the bundled languages and runtime prior to scan. Supported languages are java, go, node.js, csharp, rust |
| GITHUB_TOKEN    | GitHub personal access token with `read:packages` scope to enable package lookup during dependency and license scans                   |
| REPOSITORY_URL  | Repository URL. Useful in cases when scan is trigger from a non-git based source such as an s3 bucket                                  |
| COMMIT_SHA      | Git commit hash. This is useful while scanning non-git based source                                                                    |
| BRANCH          | Git branch name. Automatically detected for git repositories. Specify this while scanning a folder or svn repository                   |
| CREDSCAN_DEPTH  | Number of commits to audit for secrets leak. Default 2                                                                                 |
