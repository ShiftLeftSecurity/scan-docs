# Scan in CI/CD Pipelines

Scan is purpose built for integration into your workflow. Here are a few integration approaches for Scan with modern CI/CD systems:

## Repository based platforms

- [Integration with Bitbucket Pipelines](bitbucket.md)
- [Integration as Github Actions](github-actions.md)
- [Integration as Github Code scanning](code-scan.md)
- [Integration with GitLab CI](gitlab.md)

## Public cloud platforms

- [Integration with Azure DevOps Pipelines](azure-devops-pipeline.md)
- [Integration with Google CloudBuild](google-cloudbuild.md)
- [Integration with AWS CodeBuild](aws-codebuild.md)

## Dedicated CI/CD

- [Integration with Circle CI](circleci.md)
- [Integration with Jenkins CI](jenkins.md)
- [Integration with Travis CI](travis.md)
- [Integration with TeamCity](teamcity.md)

## Cloud-native CI/CD

- [D2iQ Dispatch](dispatch.md)

## Others

For CI/CD systems not listed here (TeamCity, GoCD etc), here are few things you can try:

=== "Container based job"
    - Create a container-based job or build step and use `shiftleft/scan` as the image. Some CI systems might expect the full name to be provided: `docker://shiftleft/sast-scan:latest`
    - For the command use `scan`. If this command doesn't succeed check if the source code is available and that the project is compiled. You may need to perform these steps before invoking scan.

=== "Command based step"
    This approach may not work reliably and should be used only as the last resort. Use the docker run command mentioned in the [Getting started](../getting-started/README.md)

    ```bash
    docker run --rm -e "WORKSPACE=${PWD}" -v "$PWD:/app" shiftleft/sast-scan scan
    ```

    In some CI systems, running docker command might be supported but might need some configuration to explicitly turn it on. For instance, Travis requires a service `docker` to enable docker support.

Once you manage to get it working please share the steps with us via [GitHub issues](https://github.com/ShiftLeftSecurity/scan-docs/issues) so that we can update this documentation.
