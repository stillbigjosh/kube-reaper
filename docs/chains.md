# Attack Path Chains

kube-reaper builds 12 types of multi-step attack chains. Each chain links permissions, running pods, and cluster state into a step-by-step escalation path.

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

## Chain Deduplication

Chains are deduplicated by a composite ID. The ID format depends on the chain type:

- **Namespace-specific chains** (privileged pod breakout, PSS removal): ID includes the namespace. The same chain appears once per affected namespace.
- **Identity-specific chains** (all others): ID includes only the identity. The same chain for the same identity appears once, regardless of how many namespaces the identity has access to.

This prevents duplicate chains when an identity has the same permissions across multiple namespaces (common for cluster-admin and other broadly-scoped identities).
