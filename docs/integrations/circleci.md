## Integration with CircleCI

Scan has good support for integration with CircleCI builds.

```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: shiftleft/sast-scan
    working_directory: ~/repo
    steps:
      - checkout
      - run:
          name: Perform Scan
          command: |
            scan --build
      - store_artifacts:
          path: reports
          destination: sast-scan-reports
```

To use environment variables such as `GITHUB_TOKEN` pass it to the docker step directly as shown.

```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: shiftleft/sast-scan
        environment:
          GITHUB_TOKEN: $GITHUB_TOKEN
          WORKSPACE: ${CIRCLE_REPOSITORY_URL}/blob/${CIRCLE_SHA1}
```
