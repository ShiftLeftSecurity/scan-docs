# Secure Deployment

One of the final stages in delivering secure software is ensuring the security and integrity of developed applications are not compromised during deployment. The Secure Deployment (SD) practice focuses on this. To this end, the practice’s first stream focuses on removing manual error by automating the deployment process as much as possible, and making its success contingent upon the outcomes of integrated security verification checks. It also fosters Separation of Duties by making adequately trained, non-developers responsible for deployment.

The second stream goes beyond the mechanics of deployment, and focuses on protecting the privacy and integrity of sensitive data, such as passwords, tokens, and other secrets, required for applications to operate in production environments. In its simplest form, suitable production secrets are moved from repositories and configuration files into adequately managed digital vaults. In more advanced forms, secrets are dynamically generated at deployment time and routine processes detect and mitigate the presence of any unprotected secrets in the environment.

| Maturity level | Deployment Process                                                                                        | Secret Management                                                                                                          |
| -------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Beginner       | Deployment processes are fully documented.                                                                | Formalize the deployment process and secure the used tooling and processes.                                                | Introduce basic protection measures to limit access to your production secrets. |
| Intermediate   | Deployment processes include security verification milestones.                                            | Automate the deployment process over all stages and introduce sensible security verification tests.                        | Inject secrets dynamically during deployment process from hardened storages and audit all human access to them. |
| Advanced       | Deployment process is fully automated and incorporates automated verification of all critical milestones. | Automatically verify integrity of all deployed software, indenendently on whether it's internally or externally developed. | Improve the lifecycle of application secrets by regularly generating them and by ensuring proper use. |

## External links

- [NCSC: Secure development and deployment guidance](https://www.ncsc.gov.uk/collection/developers-collection)
- [Securing Kubernetes cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/)
