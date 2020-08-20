# Use Cases for scan

Here are some use cases, where scan can help with your DevSecOps process and security compliance needs. A level of scripting and automation is required to implement these use cases depending on the technology stack used. Here GitHub is assumed to be both the repository and issue management system.

## Pre-requisites

- Python 3 is installed and available
- Install dependent pypi packages
    ```bash
    pip install PyGithub
    ```

- Scan is performed with scan results available under `reports` directory

## Automatic issue creation for critical vulnerabilities

The steps involved for this use case are:

- Parse the full report from scan called `scan-full-report.json` and extract only the `critical` findings
- Use [PyGithub](https://github.com/PyGithub/PyGithub) library (or)
- Use [JIRA Python](https://jira.readthedocs.io/en/master/examples.html) to create an issue for each finding

### Parsing the full report

`scan-full-report.json` is a single file in json lines format. Each line in this file would represent an entire [SARIF Json](../integrations/sarif.md) produced by the scanners. While attempting to parse a json lines file, extract each line and then perform a json load to convert the string to an object as shown.

```python
with open(jsonfile, mode="r") as fp:
    json_data = fp.read()
    summary = None
    for line in json_data.split("\n"):
        if not line.strip():
            continue
        try:
            sarif_data = json.loads(line)
        except as e:
            print(e)
```

If you do not prefer jsonlines, then feel to free to use the individual SARIF files that can be found under the `reports` directory. Each SARIF file can be parsed and loaded directly as a JSON file.

Once the json object `sarif_data` is obtained, use a snippet like below to extract just the critical vulnerabilities.

```python
# sev_required = ["CRITICAL", "HIGH"]
sev_required = ["CRITICAL"]
findings = [f for f in sarif_data.get("results") if f["properties"]["issue_severity"] in sev_required]
# Metadata about the repository and branch
repo_url = sarif_data["versionControlProvenance"]["repositoryUri"]
branch = sarif_data["versionControlProvenance"]["branch"]
commit_sha = sarif_data["versionControlProvenance"]["revisionId"]
```

!!! Note
    Findings is a list of results dict. See result section under [SARIF Json](../integrations/sarif.md)


### Issue creation (GitHub)

With PyGithub, the below code snippet can be used to create GitHub issues.

```python
import json

from github import Github

# using username and password
g = Github("user", "password")

# or using an access token
g = Github("access_token")

repo = g.get_repo(repo_url)

# Label to apply for the defect
label = repo.get_label("Security Issue")
# Iterate through the findings and create issues
for f in findings:
    title = "{}:{}".format("SCAN", f["message"]["text"])
    # Just dump the json as a body for now. But feel free to customize this
    body = json.dumps(f)
    # Create a GitHub issue with a title and body
    repo.create_issue(title=title, body=body, labels=[label])
```

!!! Note
    Bonus points:

    - If you can use `repo_context.invokedBy` to assign the issue to the correct developer automatically!
    - Avoid duplicates
    - Close the defects that are not found in the SARIF file but exists on GitHub based on the label `Security Issue`

    Once this is implemented please make it open-source and share it with the community!

### Issue creation (JIRA)

```python
from jira import JIRA

jac = JIRA('https://jira.atlassian.com', auth=('username', 'password'))

# Iterate through the findings and create issues
for f in findings:
    summary = "{}:{}".format("SCAN", f["message"]["text"])
    # Just dump the json as a body for now. But feel free to customize this
    description = json.dumps(f)
    issue_dict = {
        'project': {'id': 123},
        'summary': summary,
        'description': description,
        'issuetype': {'name': 'Bug'},
    }
    new_issue = jac.create_issue(fields=issue_dict)
    # Assigning to the user based on repo_context.invokedBy
    # new_issue.update(assignee={'name': 'new_user'})
    # Attaching reports to the issues
    jac.add_attachment(issue=new_issue, attachment='reports/source-js-report.html')
```

## Security assurance for deployment

Security assurance (sign-off) for deployment can be implemented in a number of ways:

- Creating a new issue for deployment and add comments with reports and approvals from various stakeholders and tools
- Creating a release or a Pull Request

In the below example, we create a new issue if there are no critical or high vulnerabilities reported. The steps involved are:

- Find an aggregate summary of all findings by severity
- Create an issue using PyGithub

### Code snippet

```python
import datetime
from github import Github

def agg_summary(summary, metrics):
    if not summary:
        summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    if metrics:
        summary["total"] += metrics["total"]
        summary["critical"] += metrics["critical"]
        summary["high"] += metrics["high"]
        summary["medium"] += metrics["medium"]
        summary["low"] += metrics["low"]
    return summary


def get_sast_summary(jsonfile):
    with open(jsonfile, mode="r") as fp:
        json_data = fp.read()
        summary = None
        for line in json_data.split("\n"):
            if not line.strip():
                continue
            try:
                sarif_data = json.loads(line)
                metrics = sarif_data.get("properties", {}).get("metrics", {})
                summary = agg_summary(summary, metrics)
            except as e:
                print(e)
        return summary


def create_release(repo_url):
    repo = g.get_repo(repo_url)
    # Label used for sign-off
    label = repo.get_label("Security Sign-Off")
    repo.create_issue(title="New release request", body="New release for {}\nSign-off: Scan at {}".format(repo_url, str(datetime.now().isoformat())), labels=[label])


def main():
    reports_dir = Path(__file__).parent / "reports"
    full_reports = [p.as_posix() for p in reports_dir.rglob("scan-full-report.json")]
    # This is a dict with repo name as the key and summary count as value
    repo_summary = {d.split("/")[1]: get_sast_summary(d) for d in full_reports}
    # This dict would have a grand summary for all repositories
    grand_summary = None
    for k, v in repo_summary.items():
        grand_summary = agg_summary(grand_summary, v)
    # Check the grand_summary for absence of critical and high vulnerabilities
    if not grand_summary["critical"] and grand_summary["high"]:
        create_release("repo url here")


if __name__ == "__main__":
    main()
```

!!! Note
    Bonus points:

    - Upload the scan HTML reports to a separate repo or a private s3 bucket and add the links to the ticket
    - Make use of GitHub code scanning
    - Use a better project management tool such as Jira or Azure Boards that support file attachments


## Software Bill-of-Materials Report

Software Bill-of-Materials SBOM is automatically produced by scan as a pre-requisite for performing dependency scanning (`depscan`). These are in xml and JSON format compatible with [CycloneDX 1.2 specification](https://cyclonedx.org/docs/1.2/) with a `bom` prefix. Refer to the [SBOM page](../integrations/sbom.md) for further information.

There are quite a number of scenarios why this report might be required by your security team:

- To track, analyze and audit the usage of open-source dependencies and their licenses
- To produce release notes and give credits for the community
- To please their boss

In the below example, we use XSLT and a bash command called `xsltproc` to produce a simple markdown table of packages and their license. Feel free to use the json format too.

- Create an XSLT file with the below and save it as `bom.xslt`

    ```xslt
    <xsl:stylesheet version="1.0" xmlns:bom="http://cyclonedx.org/schema/bom/1.2" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <xsl:output method="text" />
    <xsl:template match="/">
        <xsl:text>## Project dependencies</xsl:text>
        <xsl:text>&#xa;&#xa;</xsl:text>
        <xsl:text>| Vendor | Name | Version | License Id | </xsl:text>
        <xsl:text>&#xa;</xsl:text>
        <xsl:text>| -------|------|---------|------------|</xsl:text>
        <xsl:text>&#xa;</xsl:text>
        <xsl:for-each select="/bom:bom/bom:components/bom:component">
            <xsl:text>| </xsl:text>
            <xsl:value-of select="bom:group"/>
            <xsl:text> | </xsl:text>
            <xsl:value-of select="bom:name"/>
            <xsl:text> | </xsl:text>
            <xsl:value-of select="bom:version"/>
            <xsl:text> | </xsl:text>
            <xsl:for-each select="bom:licenses/bom:license">
                <xsl:value-of select="bom:id"/>
                <xsl:if test="position() != last()">
                    <xsl:text>, </xsl:text>
                </xsl:if>
                </xsl:for-each>
            <xsl:text> |</xsl:text>
            <xsl:text>&#xa;</xsl:text>
        </xsl:for-each>
    </xsl:template>
    </xsl:stylesheet>
    ```

- Invoke scan with `--type depscan` and wait for the reports to be generated.
- Assuming the generated `bom` file is called `bom-report.xml` inside the reports directory, execute the below bash command.

    ```bash
    xsltproc bom.xslt reports/bom-report.xml
    ```

In a future version, scan would automatically produce the html version of this report similar to the sast and dependency scan reports. Till that time, please use this suggested script.
