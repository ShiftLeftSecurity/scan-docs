## Integration with Travis CI

Here is a minimal configuration to setup scan with Travis CI,

```yaml
services:
  - docker

script:
  - docker run -v $PWD:/app shiftleft/sast-scan scan --build
```
