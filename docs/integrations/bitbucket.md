# Integration with Bitbucket Pipelines

Create a yaml file called `bitbucket-pipelines.yml` in the root directory of your project with the following configuration.

```yaml
image: shiftleft/scan:latest

pipelines:
  default:
    - step:
        script:
          - scan --build
```

![Bitbucket pipelines](img/bitbucket.png)

!!! Tip
    To add environment variables such as WORKSPACE or GITHUB_TOKEN for scan, Use `Repository Variables` under `Repository Settings` and then `Pipelines`. Such variables would automatically get picked up by scan.
