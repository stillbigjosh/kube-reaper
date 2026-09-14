# Pod Context Detection

When kube-reaper runs inside a Kubernetes pod, it automatically detects this and analyzes the pod's security context. This module runs before any API calls and does not require RBAC permissions.

## How It Works

kube-reaper checks for `/var/run/secrets/kubernetes.io/serviceaccount/token` and the `KUBERNETES_SERVICE_HOST` environment variable to determine if it runs inside a pod.

If it runs inside a pod, it inspects three categories:

1. **Service account token** - presence, path, SA name and namespace, JWT claims
2. **Filesystem mounts** - dangerous host paths, runtime sockets, sensitive files
3. **Environment variables** - leaked credentials, API keys, tokens

## Service Account Token Analysis

kube-reaper reads the projected SA token and extracts:

- **SA name and namespace** from the JWT payload (`kubernetes.io` claim)
- **Token path** (standard or custom mount)
- **Token expiration** from the JWT `exp` claim

The token is decoded without verification (no external dependencies). Only the base64-encoded payload is read.

### Findings

| Finding | Severity | When |
|---|---|---|
| SA Token Mounted | MEDIUM | A token file exists at the standard or projected path |

## Mount Analysis

kube-reaper checks for these host-mounted paths. To avoid false positives, paths that exist in every container by default (such as `/etc/shadow`, `/home`, `/root`, `/tmp`) are not flagged unless they are readable and host-mounted.

### Container runtime sockets

| Path | Severity | Risk |
|---|---|---|
| `/var/run/docker.sock` | CRITICAL | Docker socket. Create containers, escape to host. |
| `/run/docker.sock` | CRITICAL | Docker socket (alternative path). |
| `/var/run/containerd/containerd.sock` | CRITICAL | Containerd socket. Direct container runtime access. |
| `/run/containerd/containerd.sock` | CRITICAL | Containerd socket (alternative path). |
| `/var/run/crio/crio.sock` | CRITICAL | CRI-O socket. Container runtime access. |

### Kubernetes PKI and configuration

These are only flagged when specific sensitive files exist and are readable:

| File | Severity | Risk |
|---|---|---|
| `/etc/kubernetes/admin.conf` | HIGH | Full admin kubeconfig. Instant cluster-admin. |
| `/etc/kubernetes/pki/ca.key` | CRITICAL | Cluster CA private key. Forge any certificate. |
| `/etc/kubernetes/pki/apiserver.key` | CRITICAL | API server private key. |
| `/etc/kubernetes/pki/etcd/server.key` | CRITICAL | Etcd server key. Access the backing datastore directly. |

### SSH keys

These are only flagged when specific key files exist and are readable:

| File | Severity | Risk |
|---|---|---|
| `/root/.ssh/id_rsa` | HIGH | RSA private key. Lateral movement to other hosts. |
| `/root/.ssh/id_ed25519` | HIGH | Ed25519 private key. |
| `/root/.ssh/authorized_keys` | HIGH | Shows what keys have access. Add your own for persistence. |

### Host filesystem indicators

| Check | Severity | Risk |
|---|---|---|
| Host PID namespace | CRITICAL | `/proc/1/cgroup` shows the root cgroup path. Can see and ptrace host processes, read `/proc/*/environ`. |

### What is not flagged (false positive prevention)

These paths exist in every container and are not security findings:

- `/etc/shadow`, `/etc/passwd` (exist in every container image, not host-mounted)
- `/home`, `/root` (standard filesystem paths)
- `/root/.bash_history` (exists in any container where bash was used)
- `/tmp` writable (always writable in containers)
- `/etc/kubernetes`, `/etc/kubernetes/pki` (directory existence alone means nothing)

## Environment Variable Analysis

kube-reaper checks for environment variables that contain credentials. To avoid false positives, it uses exact matches and strict suffix patterns instead of substring matching.

### Exact matches

These variable names are checked exactly as written:

`VAULT_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SESSION_TOKEN`, `AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`, `DATABASE_URL`, `DB_PASSWORD`, `REDIS_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `POSTGRES_PASSWORD`, `DOCKER_PASSWORD`

### Suffix patterns

Variables that end with these suffixes are flagged:

`_PASSWORD`, `_SECRET_KEY`, `_API_KEY`, `_PRIVATE_KEY`, `_ACCESS_TOKEN`

### What is not flagged (false positive prevention)

These patterns caused false positives in earlier versions and are excluded:

- `SECRET` as a substring (matched `SECRET_BACKEND`, `SECRET_STORE_TYPE`)
- `TOKEN` as a substring (matched `TOKEN_EXPIRY`, `TOKEN_ISSUER`)
- `KEY` as a substring (matched `KEY_ROTATION_INTERVAL`, `KEY_TYPE`)
- `PASSWORD` as a substring (matched `PASSWORD_POLICY`, `PASSWORD_MIN_LENGTH`)

## API Server Reachability

If the `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` environment variables are set, kube-reaper reports the API server endpoint as an INFO finding. This confirms that the pod can reach the API server.

## Output Example

```
╔══════════════════════════════════════════════════╗
║           POD CONTEXT ANALYSIS                   ║
╚══════════════════════════════════════════════════╝
  Running inside a Kubernetes pod

    [CRITICAL] Dangerous Mount: Host PID Namespace
      Sharing host PID namespace. Can see/ptrace host processes.

    [MEDIUM] SA Token Mounted
      Token at /var/run/secrets/kubernetes.io/serviceaccount/token.
      Identity: system:serviceaccount:development:code-server

    [INFO] API Server Reachable
      API server at https://10.96.0.1:443
```
