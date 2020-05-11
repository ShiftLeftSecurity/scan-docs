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

## Storing reports

Bitbucket pipelines has a pipe called `Bitbucket upload file` which can be used to store the scan reports for reference and auditing purposes. For example, assuming that scan reports were produced in a directory called `reports`, the below snippet can be used to upload the html file.

```yaml
- pipe: atlassian/bitbucket-upload-file:0.1.4
    variables:
      BITBUCKET_USERNAME: $BITBUCKET_USERNAME
      BITBUCKET_APP_PASSWORD: $BITBUCKET_APP_PASSWORD
      FILENAME: 'reports/source-report.html'
```

!!! Note
    This pipe requires an app password with `Repositories write and read` permissions.
