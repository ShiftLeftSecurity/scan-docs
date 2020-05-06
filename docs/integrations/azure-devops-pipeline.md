## Integration with Azure DevOps Pipelines

ShiftLeft Scan has a best-in-class integration for Azure Pipelines with our dedicated [extension](https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.sl-scan-results). To being integration,

1. Install the extension to your Azure DevOps Organization. Ask your administrator for help if you do not have this permission.

2. Simply add the following snippet to your build configuration YAML file (Usually azure-pipelines.yml).

   ```yaml
   - script: |
       docker run \
         -v "$(Build.SourcesDirectory):/app:cached" \
         -v "$(Build.ArtifactStagingDirectory):/reports:cached" \
         shiftleft/sast-scan scan --src /app \
         --out_dir /reports/CodeAnalysisLogs
     displayName: "Perform ShiftLeft Scan"
     continueOnError: "true"

   - task: PublishBuildArtifacts@1
     displayName: "Publish analysis logs"
     inputs:
       PathtoPublish: "$(Build.ArtifactStagingDirectory)/CodeAnalysisLogs"
       ArtifactName: "CodeAnalysisLogs"
       publishLocation: "Container"
   ```

3. Trigger a build as normal and wait for it to complete.

4. From the Pipelines page, select the most recent run. You should see a tab called **ShiftLeft Scan** as shown below.

   ![Scan Tab](img/scan-tab.png)

5. Individual scan reports are shown as tabs as seen below. You can click on any tab to view and audit the different reports

   ![Reports](img/scan-report.png)

6. Summary would also be available in the build console logs for easy reference

   ![Console logs](img/build-log-summary.png)

### Container jobs based pipelines

By default, jobs run on the host machine where the agent is installed. This is convenient and typically well-suited for projects that are just beginning to adopt Azure Pipelines. On Linux and Windows agents, jobs may be run on the host or in a [container](https://docs.microsoft.com/en-us/azure/devops/pipelines/process/container-phases?view=azure-devops). ShiftLeft scan support such container jobs based pipelines. Use `container: shiftleft/sast-scan:latest` as shown.

```yaml
pool:
  vmImage: 'ubuntu-latest'
container: shiftleft/sast-scan:latest
steps:
# This integrates ShiftLeft Scan with automatic build
- script: scan --build --out_dir $(Build.ArtifactStagingDirectory)/CodeAnalysisLogs
  env:
    WORKSPACE: https://github.com/prabhu/HelloShiftLeft/blob/$(Build.SourceVersion)
    GITHUB_TOKEN: $(GITHUB_TOKEN)
  displayName: "Perform ShiftLeft scan"
  continueOnError: "true"

# To integrate with the ShiftLeft Scan Extension it is necessary to publish the CodeAnalysisLogs folder
# as an artifact with the same name
- task: PublishBuildArtifacts@1
  displayName: "Publish analysis logs"
  inputs:
    PathtoPublish: "$(Build.ArtifactStagingDirectory)/CodeAnalysisLogs"
    ArtifactName: "CodeAnalysisLogs"
    publishLocation: "Container"
```

Further, by adding `--build` argument with scan command supported projects such as java, csharp, go or node.js can also be built on the fly thus speeding up the analysis. Please use container job based pipelines if your organization supports.

### Advanced configuration

You can improve the quality of the dependency scan (`--type depscan`) by passing a `GITHUB_TOKEN` as an environment variable. This token should have the following scopes:

- read:packages

```yaml
- script: |
    docker run \
      -e "GITHUB_TOKEN=$(GITHUB_TOKEN)" \
      -v "$(Build.SourcesDirectory):/app:cached" \
      -v "$(Build.ArtifactStagingDirectory):/reports:cached" \
      shiftleft/sast-scan scan --src /app \
      --out_dir /reports/CodeAnalysisLogs
  displayName: "Perform ShiftLeft Scan"
  continueOnError: "true"
```

Refer to this [configuration](https://github.com/AppThreat/WebGoat/blob/develop/azure-pipelines-sl.yml) as an example.
