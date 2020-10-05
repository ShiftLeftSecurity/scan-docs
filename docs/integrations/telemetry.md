# Telemetry for scan invocations

Telemetry is a strongly contested feature in the open-source and sometimes even in the enterprise community. There are numerous benefits from a telemetry service as part of a scan rollout in your organization. For instance, it is possible to understand the security posture of the entire organization and the individual teams based on the aggregation of data. With scan, it is possible to enable telemetry to collect the data internally for easy compliance reporting and audit


!!! Note
    Scan comes with telemetry disabled by default.


## Rollout your own service

When scan completes its invocation, a single JSON message is POSTed with the following structure.

```json
{
    "scan_mode": "Scan mode. Defaults to ci",
    "tool": "Set to @ShiftLeft/scan. Consider changing this value if you intend to fork and customize scan",
    "id": "Unique uuid for each invocation. This value would match runGuid property in the sarif reports",
    "repo_context: {
        "branch": "Repository branch",
        "pullRequest": "Boolean indicating pull request",
        "repositoryName": "Repository name",
        "repositoryUri": "Remote url",
        "revisionId": "Commit sha",
        "invokedBy: "User invoking the pipeline or the cli command"
    },
    "repo_type": ["List of language scanners used by scan"],
    "report_summary": {
        "Full name of the scanner": {
            "critical": <number>,
            "high": <number>,
            "medium": <number>,
            "low": <number>,
            "status": "Unicode cross (❌) or tick (✅)",
            "tool": "Full name of the scanner"
        }
    }
}
```

Example REST service in python to receive this message.

```python
@app.route("/track", methods=["POST"])
async def track():
    req_json = await request.get_json()
    if req_json:
        id = req_json.get("id", str(uuid.uuid4()))
        // Store req_json in a database
    return {"success": "true"}
```

### Use cases

??? tip "Find the aggregate for all applications belonging to a team"

    - Retrieve the list of findings by filtering based on `repo_context.repositoryName` or `repo_context.repositoryUrl`
    - Aggregate based on report_summary or report_summary.<Name of the scanner>

??? tip "Who to speak to about a given project?"

    - Retrieve the list of findings by filtering based on `repo_context.repositoryName` or `repo_context.repositoryUrl`
    - List unique `invokedBy`

??? tip "Status of all Node.js applications"

    - Retrieve the list of findings by filtering based on `repo_type = nodejs`
    - Aggregate based on `report_summary.key = "Source code analyzer for JavaScript"`
