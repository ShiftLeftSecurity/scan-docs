## Integration with Google CloudBuild

Here is a minimal configuration to setup scan with Google CloudBuild,

```yaml
steps:
  - name: shiftleft/sast-scan
    entrypoint: scan --build
```

Build the project before scanning and substitute for Workspace and GitHub package lookups.

```yaml
steps:
  - name: shiftleft/sast-scan
    entrypoint: /usr/local/src/scan --build
    env:
      - "WORKSPACE=https://github.com/$REPO_NAME/blob/$COMMIT_SHA"
      - "GITHUB_TOKEN=${_GITHUB_TOKEN}"

substitutions:
  _GITHUB_TOKEN: Token with read:packages scope
```

In the above configuration, `GITHUB_TOKEN` is passed as an environment variable. This token should have the following scopes:

- read:packages
