# Scan SBOM format

This document describes the output Software Bill-of-Materials (SBOM) XML and JSON format emitted by `scan` tool for integration purposes.

## SBOM specification

Software Bill-of-Materials SBOM is automatically produced by scan as a pre-requisite for performing dependency scanning (`depscan`). This files are in XML and JSON format compatible with [CycloneDX 1.2 specification](https://cyclonedx.org/docs/1.2/) with a `bom` prefix.

!!! Note
    SBOM file will not be generated if scan is invoked with a specific type argument. Eg: `--type java`.<br>
    In such cases, manually pass either `depscan`, or `bom` as a type. Eg: `--type java,bom`

## CycloneDX Properties

### Global declarations

```xml
<?xml version="1.0" encoding="utf-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.2" serialNumber="urn:uuid:a4b5715e-8489-4855-8a3c-bafe5ddf7daa" version="1">
```

- xmlns: Set to `http://cyclonedx.org/schema/bom/1.2`
- serialNumber: Random UUID to uniquely represent the BOM file
- version: Set to `1` always

In case of JSON format

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.2",
  "serialNumber": "urn:uuid:1ec5994a-ae26-4ff7-9eb3-b54be8abdc6b",
  "version": 1,
  "metadata": {
    "timestamp": "2020-07-21T09:43:56Z",
    "tools": [{
      "vendor": "AppThreat",
      "name": "cdxgen",
      "version": "2.0.2",
...
```

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

This is currently unavailable in json format.

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

In JSON format, a component block would look like this

```json
"components": [
    {
      "type": "library",
      "bom-ref": "pkg:maven/org.projectlombok/lombok@1.18.4?type=jar",
      "group": "org.projectlombok",
      "name": "lombok",
      "version": "1.18.4",
      "description": "Spice up your java: Automatic Resource Management, automatic generation of getters, setters, equals, hashCode and toString, and more!",
      "hashes": [
        {
          "alg": "MD5",
          "content": "a27a7ed4f61fa3424262cce02b76fde4"
        },
        {
          "alg": "SHA-1",
          "content": "7103ab519b1cdbb0642ad4eaf1db209d905d0f96"
        },
        {
          "alg": "SHA-256",
          "content": "39f3922deb679b1852af519eb227157ef2dd0a21eec3542c8ce1b45f2df39742"
        },
        {
          "alg": "SHA-384",
          "content": "cff0617843fecbc7f29f18a51800160cb090a783ab1c07337a4df5999a2242dbfbc7774bd2ac57533d2c60ff7ef1405a"
        },
        {
          "alg": "SHA-512",
          "content": "cadcaf33ec413fdc47de1925c1a4af9a00a47b647b7aec2e826c7dc7a2cd2bb42698a3b89d2b8da7a8b781705c79cc5ed0334774c54af3602f7483e5abad61f1"
        },
        {
          "alg": "SHA3-256",
          "content": "f73a1f358c1478c91b1113dd3bda5651a1c02c2ffc3c07d33624588e4a3ba1ce"
        },
        {
          "alg": "SHA3-384",
          "content": "b877d1c07ec5f391ca48ec69226faa467f190d3e82077342b8e3e268b0ad63097d2e4fe38b643e3b5def6aad4be28422"
        },
        {
          "alg": "SHA3-512",
          "content": "64eecfb5ee90348fc5ca084006610a348b8c542eebd9747b5c78e503e56247083eef1399336f0e425d14427ecd3760905ec4ec42bde39bd56101b0e8a242aadf"
        }
      ],
      "licenses": [{"license": {"id": "MIT"}}],
      "purl": "pkg:maven/org.projectlombok/lombok@1.18.4?type=jar",
      "externalReferences": [
        {
          "type": "issue-tracker",
          "url": "https://github.com/rzwitserloot/lombok/issues"
        },
        {
          "type": "vcs",
          "url": "http://github.com/rzwitserloot/lombok"
        }
      ]
    },
...
```

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

In JSON format

```json
"externalReferences": [
  {
    "type": "issue-tracker",
    "url": "https://github.com/rzwitserloot/lombok/issues"
  },
  {
    "type": "vcs",
    "url": "http://github.com/rzwitserloot/lombok"
  }
]
```
