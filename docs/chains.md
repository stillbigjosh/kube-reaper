# Attack Path Chains

kube-reaper builds 18 types of multi-step attack chains. Each chain links permissions, running pods, and cluster state into a step-by-step escalation path.

Chains are deduplicated by ID. The same chain type for the same identity is shown once, not once per namespace (except where namespace matters, such as privileged pod breakout and PSS removal).

## Chain Types

### 1. Privileged Pod Breakout

**Severity:** CRITICAL
**Requires:** `create pods` + a namespace with no PSS enforcement
**Final capability:** Node Breakout

Steps:
1. Create a privileged pod with hostPID, hostNetwork, and hostPath:/
2. Exec into the pod
3. `chroot /mnt` for a root shell on the worker node

This chain fires once per namespace that lacks PSS enforcement.

### 2. RBAC Self-Escalation (ClusterRoleBinding)

**Severity:** CRITICAL
**Requires:** `create clusterrolebindings`
**Final capability:** Cluster Admin Takeover

Steps:
1. Create a ClusterRoleBinding that binds cluster-admin to your identity

One step to full cluster-admin.

### 3. RBAC Self-Escalation (Role + RoleBinding)

**Severity:** CRITICAL
**Requires:** `create roles` + `create rolebindings`
**Final capability:** Privilege Escalation

Steps:
1. Create a Role with broad permissions (get secrets, create pods, etc.)
2. Create a RoleBinding that binds the new Role to your identity

### 4. RBAC Escalation Prevention Bypass

**Severity:** CRITICAL
**Requires:** `escalate` verb on `roles` or `clusterroles`
**Final capability:** Cluster Admin Takeover

Steps:
1. Use the `escalate` verb to add any permission to any Role or ClusterRole

This bypasses the Kubernetes RBAC escalation prevention check. The `escalate` verb lets you grant permissions you do not have yourself.

### 5. Exec Lateral Movement

**Severity:** HIGH
**Requires:** `create pods/exec`
**Final capability:** Lateral Movement

Steps:
1. `kubectl exec` into a target pod
2. Read the SA token at `/var/run/secrets/kubernetes.io/serviceaccount/token`
3. Authenticate to the API server with the new token
4. Enumerate the new identity's permissions with kube-reaper

### 6. Ephemeral Container Injection

**Severity:** HIGH
**Requires:** `create` or `update` or `patch` on `pods/ephemeralcontainers`
**Final capability:** Code Execution

Steps:
1. Inject an ephemeral debug container into a running pod

Stealthier than exec. Does not restart the pod. The ephemeral container runs in the pod's namespace and can access its SA token.

### 7. Secret Harvest

**Severity:** HIGH
**Requires:** `get` or `list` on `secrets`
**Final capability:** Credential Harvest

Steps:
1. `kubectl get secrets` to list all secrets in the namespace
2. Decode SA token secrets (base64)
3. Authenticate with the harvested tokens to pivot to new identities

### 8. Impersonation

**Severity:** CRITICAL
**Requires:** `impersonate` on `users`, `groups`, or `serviceaccounts`
**Final capability:** Cluster Admin Takeover or Identity Forge

Steps (users/groups):
1. `kubectl --as=system:admin` or `--as-group=system:masters`
2. You now act as cluster admin

Steps (service accounts):
1. `kubectl --as=system:serviceaccount:<ns>:<sa>`
2. You now act as any SA in any namespace

### 9. Webhook Backdoor

**Severity:** HIGH
**Requires:** `create` or `update` on `mutatingwebhookconfigurations`
**Final capability:** Persistent Backdoor

Steps:
1. Deploy a webhook server pod
2. Register a MutatingWebhookConfiguration
3. All new pods get your sidecar container injected

This is a cluster-wide persistent backdoor. It survives until the webhook configuration is deleted.

### 10. PSS Removal Bypass

**Severity:** CRITICAL
**Requires:** `patch namespaces` + `create pods`
**Final capability:** Node Breakout

Steps:
1. Patch the namespace to remove the `pod-security.kubernetes.io/enforce` label
2. PSS enforcement is now disabled in that namespace
3. Deploy a privileged pod with host mounts
4. Break out to the node

This chain fires once per namespace that has PSS enforcement.

### 11. Token Forging

**Severity:** CRITICAL
**Requires:** `create serviceaccounts/token`
**Final capability:** Identity Forge

Steps:
1. Create a TokenRequest for a privileged SA in the namespace
2. Receive a valid JWT token for that SA
3. Authenticate as the SA

This works even without `get secrets` access. The TokenRequest API mints fresh tokens.

### 12. PV Breakout

**Severity:** HIGH
**Requires:** `create persistentvolumes` + `create persistentvolumeclaims` + `create pods`
**Final capability:** Node Breakout

Steps:
1. Create a PersistentVolume with `hostPath: /`
2. Create a PersistentVolumeClaim that binds to the PV
3. Create a pod that mounts the PVC
4. Access the host filesystem inside the pod

This is an alternative node breakout path. It works in some PSS-restricted namespaces where direct hostPath mounts are blocked.

### 13. CSR Forging

**Severity:** CRITICAL
**Requires:** `create certificatesigningrequests` + `update certificatesigningrequests/approval`
**Final capability:** Cluster Admin Takeover

Steps:
1. Create a CertificateSigningRequest with `O=system:masters` in the subject
2. Approve the CSR
3. Download the signed certificate
4. Use the certificate for persistent cluster-admin access

This creates a client certificate that does not expire when the CA rotates tokens.

### 14. Pod Pivot

**Severity:** HIGH or CRITICAL (depends on target SA)
**Requires:** `create pods/exec` or `create pods/attach` + running pods with overprivileged SAs
**Final capability:** Lateral Movement, Privilege Escalation, or Cluster Admin Takeover

Steps:
1. Exec or attach into a target pod
2. Read the pod's mounted SA token
3. The SA has dangerous permissions (listed in the chain)

This chain cross-references three data sources:
- Your exec/attach permissions
- Running pods and their service accounts
- Each SA's effective RBAC permissions from the RBAC graph

The chain shows what pod to target, what SA it runs as, and what permissions that SA has. Pod pivot chains include flags for additional risk factors: `[privileged]`, `[hostPID]`, `[hostPath]`.

### 15. Exec into Dangerous Pod

**Severity:** CRITICAL
**Requires:** `create pods/exec` or `create pods/attach` + running pods with privileged, hostPID, or sensitive hostPath mounts
**Final capability:** Node Breakout or Credential Harvest

Steps:
1. Exec or attach into an already-running dangerous pod
2. If privileged with hostPath:/: `chroot /mnt` for root shell on the node
3. If privileged without root mount: `nsenter --target 1 --mount --uts --ipc --net --pid` or read `/proc/1/root`
4. If hostPath only: read credentials from mounted host filesystem

This is the shortest path to node access when a dangerous pod already exists. Unlike chain type 1 (Privileged Pod Breakout), you do not need `create pods`. You reuse what is already running. This chain is reported alongside the longer create-your-own-pod path when both are available.

### 16. SA Spec Identity Pivot

**Severity:** HIGH or CRITICAL (depends on target SA)
**Requires:** `create pods` in a namespace + target SA with dangerous permissions in the same namespace
**Final capability:** Lateral Movement, Privilege Escalation, or Cluster Admin Takeover

Steps:
1. Create a pod with `serviceAccountName` set to the target SA
2. The API server mounts a projected token for that SA automatically
3. Read the token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
4. Authenticate as the target SA

This chain does not require `get secrets` or `create serviceaccounts/token`. It only needs `create pods`. The projected token is mounted by the API server as part of normal pod creation. The chain cross-references pod creation permissions with the RBAC graph to find SAs worth targeting.

### 17. Workload Mutation Identity Theft

**Severity:** HIGH or CRITICAL (depends on target SA)
**Requires:** `patch` or `update` on `deployments`, `daemonsets`, or `statefulsets` + target SA with dangerous permissions in the same namespace
**Final capability:** Lateral Movement, Privilege Escalation, or Cluster Admin Takeover

Steps:
1. Patch the workload's `serviceAccountName` to a target SA with dangerous permissions
2. Wait for rollout. New pods mount a projected token for the target SA
3. Read the token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
4. Authenticate as the target SA

This chain differs from SA Spec Identity Pivot (chain type 16) because it does not require `create pods`. It hijacks existing workloads instead. DaemonSet mutations run on every node, giving cluster-wide code execution. StatefulSet mutations persist across restarts because of stable storage. The chain cross-references patch/update permissions with the RBAC graph to find SAs worth targeting.

One chain is emitted per (identity, namespace, target SA) combination. The chain lists all patchable workload types the identity has access to (Deployment, DaemonSet, StatefulSet) in a single finding to reduce noise.

### 18. Webhook Backend Takeover

**Severity:** HIGH
**Requires:** `list` on `mutatingwebhookconfigurations` + `patch` or `update` on `deployments`
**Final capability:** Persistent Backdoor

Steps:
1. List MutatingWebhookConfigurations to find which Service backends serve admission webhooks
2. Identify the Deployment behind the webhook backend Service
3. Patch the backend Deployment to inject attacker code into the webhook handler
4. All future pod creates and updates pass through the compromised admission webhook

This chain differs from Webhook Backdoor (chain type 9) because it does not require `create mutatingwebhookconfigurations`. Instead of registering a new webhook, it takes over the Deployment that serves an existing webhook's backend. This is stealthier because no new webhook appears in the API server.

This chain is suppressed when the identity can create MutatingWebhookConfigurations directly, since the Webhook Backdoor path (chain type 9) is simpler. The chain requires existing MutatingWebhookConfigurations in the cluster to be actionable.

## Chain Deduplication

Chains are deduplicated by a composite ID. The ID format depends on the chain type:

- **Namespace-specific chains** (privileged pod breakout, PSS removal): ID includes the namespace. The same chain appears once per affected namespace.
- **Identity-specific chains** (all others): ID includes only the identity. The same chain for the same identity appears once, regardless of how many namespaces the identity has access to.

This prevents duplicate chains when an identity has the same permissions across multiple namespaces (common for cluster-admin and other broadly-scoped identities).
