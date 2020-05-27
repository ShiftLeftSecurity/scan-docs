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

Below is an example.

```json
{
  "scan_type": "java,credscan,bash",
  "scan_tools_args_map": {
    "credscan": [
      "gitleaks",
      "--branch=master",
      "--repo-path=%(src)s",
      "--redact",
      "--report=%(report_fname_prefix)s.json",
      "--report-format=json"
    ]
  }
}
```

With a local config you can override the scan type and even configure the command line args for the tools as shown.

## Use CI build reference as runGuid

By setting the environment variable `SCAN_ID` you can re-use the CI build reference as the run guid for the reports. This is useful to reverse lookup the pipeline result based on the scan result.

## Creating bash alias

Add the below alias to your .bashrc or .zshrc file to simplify the scan command for terminal invocations.

```bash
scan() {
    docker run --rm -e "WORKSPACE=$(pwd)" -e GITHUB_TOKEN -v "$(pwd):/app:cached" shiftleft/scan scan $*
}
```

To perform scan with this alias, simply use the word scan

```bash
scan --type java
```

This approach seems to work with Linux, Mac and WSL 1 and 2 for Windows.
