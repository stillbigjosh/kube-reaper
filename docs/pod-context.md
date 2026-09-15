# Pod Context Detection

When kube-reaper runs inside a Kubernetes pod, it automatically detects this and analyzes the pod's security context. This module runs before any API calls and does not require RBAC permissions.

## How It Works

kube-reaper checks for `/var/run/secrets/kubernetes.io/serviceaccount/token` and the `KUBERNETES_SERVICE_HOST` environment variable to determine if it runs inside a pod.

If it runs inside a pod, it inspects these categories:

1. **Container escape vectors** - privileged mode, host filesystem mounts, core_pattern, cgroup release_agent, sysrq-trigger
2. **Linux capabilities** - dangerous effective capabilities from `/proc/self/status`
3. **Cloud metadata (IMDS)** - AWS (IMDSv1 and IMDSv2), GCP, and Azure metadata endpoints
4. **Network** - non-loopback interfaces and listening TCP ports
5. **Service account token** - presence, path, SA name and namespace, JWT claims
6. **Filesystem mounts** - dangerous host paths, runtime sockets, sensitive files
7. **Environment variables** - leaked credentials, API keys, tokens

## Container Escape Vector Detection

kube-reaper checks for conditions that let a container break out to the host. Each check reads the local filesystem. No API calls are necessary.

| Check | Vector Type | Severity | How It Works |
|---|---|---|---|
| `/sys/kernel/mm` writable | Privileged Container | CRITICAL | The tool checks if the effective UID can write to this path. A writable `/sys/kernel/mm` shows that the container is privileged. |
| `/proc/1/root` has host content | Host Root Filesystem | CRITICAL | The tool reads `/proc/1/comm`. If PID 1 is `systemd`, `init`, or `launchd`, the host root filesystem is exposed. |
| `/host`, `/hostfs`, `/rootfs`, `/node-root` | Host Filesystem Mount | CRITICAL | The tool checks if these directories exist and have more than 2 entries. |
| `/proc/sys/kernel/core_pattern` writable | Core Pattern Escape | CRITICAL | Write a pipe command to this file. The host runs that command when a process crashes. |
| `/sys/fs/cgroup/*/release_agent` writable | Cgroup Release Agent | CRITICAL | The tool scans all cgroup v1 controllers for a writable `release_agent` file. |
| `/proc/sysrq-trigger` writable | SysRq Trigger | HIGH | This file can crash, reboot, or dump host memory. |
| UID 0 in `/proc/self/status` | Running as Root | MEDIUM | The tool reads the `Uid` line. Root (UID 0) combined with capabilities or mounts can lead to escape. |

### Write check accuracy

The `is_writable()` function reads the file's owner UID, group GID, and permission mode. It then compares these against the effective UID and GID of the process. If the process is root (UID 0), the function returns true. If the process is not root, it checks the correct permission bits for owner, group, or other. This prevents false positives when `/proc` and `/sys` files are owned by root but the container runs as a non-root user.

## Linux Capabilities Detection

kube-reaper reads the `CapEff` field from `/proc/self/status`. It converts the hex bitmask to a list of set capabilities. Only dangerous capabilities are reported.

If all capabilities are set (bits 0-40), the tool reports one "ALL CAPABILITIES" finding and does not list each capability separately.

| Capability | Severity | Risk |
|---|---|---|
| CAP_SYS_ADMIN | CRITICAL | Mount filesystems, manipulate namespaces, cgroup escape. Primary container breakout vector. |
| CAP_SYS_MODULE | CRITICAL | Load and unload kernel modules. Kernel-level code execution. |
| CAP_SYS_RAWIO | CRITICAL | Raw I/O port access. Direct hardware control. |
| CAP_SYS_PTRACE | HIGH | Trace any process. Code injection into host processes when hostPID is set. |
| CAP_DAC_OVERRIDE | HIGH | Bypass file write permissions. Write to any file. |
| CAP_DAC_READ_SEARCH | HIGH | Bypass file read permissions. Read any file. |
| CAP_BPF | HIGH | Load eBPF programs. Kernel-level data access. |
| CAP_NET_ADMIN | HIGH | Full network control. Sniff traffic, ARP spoof, change routes. |
| CAP_NET_RAW | HIGH | Raw sockets. Network sniffing and packet injection. |
| CAP_SETUID | HIGH | Change process UID. Escalate to root with `setuid(0)`. |
| CAP_SETGID | HIGH | Change process GID. Escalate to any group. |
| CAP_MKNOD | HIGH | Create device nodes. Access host block devices. |
| CAP_PERFMON | MEDIUM | Performance monitoring. Kernel-level side-channel attacks. |
| CAP_SYS_BOOT | MEDIUM | Reboot the host system. |

## Cloud Metadata (IMDS) Detection

kube-reaper sends HTTP requests to `169.254.169.254` to check for cloud metadata services. It uses raw TCP sockets with a 2-second timeout. No external dependencies are necessary.

| Provider | Method | What It Checks |
|---|---|---|
| AWS IMDSv1 | `GET /latest/meta-data/` | If this succeeds, it also tries to read the IAM role name and gives the curl command to get credentials. |
| AWS IMDSv2 | `PUT /latest/api/token` | If IMDSv1 fails but the PUT returns a token, IMDSv2 is available. The tool reports the two-step process. |
| GCP | `GET /computeMetadata/v1/...` with `Metadata-Flavor: Google` header | If this succeeds, the tool reads the service account email and gives the curl command to get an OAuth token. |
| Azure | `GET /metadata/instance?api-version=2021-02-01` with `Metadata: true` header | If this succeeds, the tool gives the curl command to get a managed identity token. |

All IMDS findings have CRITICAL severity. Access to cloud metadata can give credentials that control cloud resources outside the cluster.

## Network Enumeration

kube-reaper reads the local network state. No API calls are necessary.

**Interfaces**: The tool reads `/sys/class/net/` and lists all interfaces except `lo`. Known CNI interfaces (names that start with `cali`, `tunl`, `vxlan`, `flannel`, `cni`, `veth`, `docker`, `cbr`, `dummy`, `kube-ipvs`, `cilium`, `lxc`, or `wg`) are filtered out before analysis. If more than one non-CNI interface remains, the tool reports this as a MEDIUM finding. This indicates that hostNetwork is enabled.

**Listening ports**: The tool reads `/proc/net/tcp` and `/proc/net/tcp6`. It reports all sockets in LISTEN state (state `0A`) as INFO findings. It converts the hex addresses and ports to human-readable format.

## kubectl-less Mode

If the kube API client fails to connect and the binary runs inside a pod, kube-reaper does not exit. It runs in kubectl-less mode and reports only local findings:

- Container escape vectors
- Linux capabilities
- Cloud metadata (IMDS)
- Network interfaces and listening ports
- SA token, mounts, and environment variables

This mode is useful when a pod has no RBAC permissions or when the API server is not reachable. The tool reads the SA token from disk to show the pod identity in the output.

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

    [CRITICAL] Escape: Privileged Container
      Container is privileged. Mount host filesystem:
      mkdir /mnt/host && mount /dev/sda1 /mnt/host

    [CRITICAL] Escape: Core Pattern Escape
      core_pattern writable. Write |/path/to/payload to
      execute on host when a process crashes.

    [HIGH] Escape: SysRq Trigger
      SysRq trigger writable. Can crash, reboot, or dump host memory.

    [MEDIUM] SA Token Mounted
      Token at /var/run/secrets/kubernetes.io/serviceaccount/token.
      Identity: system:serviceaccount:development:code-server

    [INFO] API Server Reachable
      API server at https://10.96.0.1:443

    [INFO] Listening Ports
      Ports: 0.0.0.0:8080
```
