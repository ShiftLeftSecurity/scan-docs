# Scan SBOM format

This document describes the output Software Bill-of-Materials (SBOM) xml format emitted by `scan` tool for integration purposes.

## SBOM specification

Software Bill-of-Materials SBOM is automatically produced by scan as a pre-requisite for performing dependency scanning (`depscan`). This file is an xml file compatible with [CycloneDX 1.1 specification](https://cyclonedx.org/docs/1.1/) with a `bom` prefix. Some example bom files can be found [here](https://github.com/AppThreat/dep-scan/tree/master/test/data)

!!! Note
    SBOM file will not be generated if scan is invoked with a specific type argument. Eg: `--type java`.<br>
    In such cases, manually pass either `depscan`, or `bom` as a type. Eg: `--type java,bom`

## CycloneDX Properties

### Global declarations

```xml
<?xml version="1.0" encoding="utf-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.1" serialNumber="urn:uuid:a4b5715e-8489-4855-8a3c-bafe5ddf7daa" version="1">
```

- xmlns: Set to `http://cyclonedx.org/schema/bom/1.1`
- serialNumber: Random UUID to uniquely represent the BOM file
- version: Set to `1` always

### Metadata

Scan stores certain metadata such as `Base path` and `Package file` in a global `externalReferences` tag. This should not be confused with `externalReferences` that are specific for each `component`.

```xml
<externalReferences>
    <reference type="other">
      <url>/app</url>
      <comment>Base path</comment>
    </reference>
    <reference type="other">
      <url>/app/go.sum</url>
      <comment>Package file</comment>
    </reference>
</externalReferences>
```

### Components

Following externalReferences, all identified project dependencies would be expressed as `component` inside a `components` tag.

```xml
<components>
    <component type="library" bom-ref="pkg:golang/github.com/OneOfOne/xxhash@v1.2.2">
      <group>github.com/OneOfOne</group>
      <name>xxhash</name>
      <version>v1.2.2</version>
      <description/>
      <hashes>
        <hash alg="SHA-256">1d276994c8d9292981a80c60e6f3e3d939910e67e4cf0f9c4f300495696385c5</hash>
      </hashes>
      <licenses>
        <license>
          <id>Apache-2.0</id>
        </license>
      </licenses>
      <purl>pkg:golang/github.com/OneOfOne/xxhash@v1.2.2</purl>
    </component>
```

- type: Mostly `library`. Other possible values are application, framework, library, operating-system, device, or file.
- bom-ref: Unique string to represent this component reference
- group: Group or domain name of the publisher. Special characters are allowed
- name: Name of the component in the shortened form
- version: Component version
- Description: Optional description about the package
- Hash: Hash of the packages as provided by the registry. Note: currently hash values are not reliable due to the non-reproducible nature of many open-source dependencies
- Licenses: List of license specified for the component. One or more of the below properties will be available:
    - `id`: SPDX license id for accurate matches. This would be unavailable in cases where the license name or url cannot be matched accurately
    - `name`: License name
    - `url`: URL to the original license file.
    
!!! Note    
    In some cases, only the URL property would be available. This could well mean that the package is licensed under some terms that is not compatible with the OSI recommended license clauses.<br>This might also happen with packages where typos or unexpected paragraph breaks are used in the license file.

- purl: Package URL string as specified [here](https://github.com/package-url/purl-spec)

### Component - External references

Component could have external references such as `website` or `issue-tracker` or `vcs`

```xml
<externalReferences>
        <reference type="website">
          <url>https://github.com/visionmedia/bytes.js#readme</url>
        </reference>
        <reference type="issue-tracker">
          <url>https://github.com/visionmedia/bytes.js/issues</url>
        </reference>
        <reference type="vcs">
          <url>git+https://github.com/visionmedia/bytes.js.git</url>
        </reference>
</externalReferences>
```
