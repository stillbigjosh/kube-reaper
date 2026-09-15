use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PodContext {
    pub running_in_pod: bool,
    pub sa_token_mounted: bool,
    pub sa_name: Option<String>,
    pub sa_namespace: Option<String>,
    pub token_path: Option<String>,
    pub ca_cert_path: Option<String>,
    pub api_server_env: Option<String>,
    pub interesting_env_vars: Vec<InterestingEnvVar>,
    pub interesting_mounts: Vec<InterestingMount>,
    pub writable_paths: Vec<String>,
    pub capabilities: Vec<CapabilityInfo>,
    pub cloud_metadata: Vec<CloudMetadataFinding>,
    pub escape_vectors: Vec<EscapeVector>,
    pub network_info: Option<NetworkInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterestingEnvVar {
    pub name: String,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterestingMount {
    pub path: String,
    pub mount_type: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityInfo {
    pub name: String,
    pub dangerous: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudMetadataFinding {
    pub provider: String,
    pub accessible: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EscapeVector {
    pub vector_type: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<String>,
    pub listening_ports: Vec<ListeningPort>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListeningPort {
    pub port: u16,
    pub address: String,
    pub protocol: String,
}

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SA_NS_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const SA_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

const SENSITIVE_ENV_EXACT: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY_ID", "AWS access key in environment"),
    ("AWS_SECRET_ACCESS_KEY", "AWS secret key in environment"),
    ("AZURE_CLIENT_SECRET", "Azure credential in environment"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "GCP credential path in environment"),
    ("DATABASE_URL", "Database connection string in environment"),
    ("VAULT_TOKEN", "HashiCorp Vault token in environment"),
    ("GITHUB_TOKEN", "GitHub token in environment"),
    ("GITLAB_TOKEN", "GitLab token in environment"),
    ("SLACK_TOKEN", "Slack token in environment"),
    ("DOCKER_PASSWORD", "Docker registry password in environment"),
    ("REGISTRY_PASSWORD", "Container registry password in environment"),
    ("KUBECONFIG", "Kubeconfig path in environment"),
];

const SENSITIVE_ENV_SUFFIXES: &[(&str, &str)] = &[
    ("_PASSWORD", "Password in environment"),
    ("_SECRET_KEY", "Secret key in environment"),
    ("_API_KEY", "API key in environment"),
    ("_APIKEY", "API key in environment"),
    ("_PRIVATE_KEY", "Private key in environment"),
    ("_ENCRYPTION_KEY", "Encryption key in environment"),
    ("_DB_PASSWORD", "Database password in environment"),
    ("_REDIS_PASSWORD", "Redis password in environment"),
];

const HOST_ONLY_PATHS: &[(&str, &str, &str)] = &[
    ("/var/run/docker.sock", "Docker Socket", "Docker socket mounted. Container escape via docker commands."),
    ("/run/containerd/containerd.sock", "Containerd Socket", "Containerd socket mounted. Container escape via ctr/crictl."),
    ("/var/run/crio/crio.sock", "CRI-O Socket", "CRI-O socket mounted. Container escape via crictl."),
];

const SENSITIVE_FILE_CHECKS: &[(&str, &str, &str)] = &[
    ("/etc/shadow", "Host Shadow File", "Host shadow file readable. Extract hashes for offline cracking."),
    ("/etc/kubernetes/admin.conf", "Cluster Admin Kubeconfig", "Cluster admin kubeconfig readable. Direct cluster-admin access."),
    ("/etc/kubernetes/pki/ca.key", "Cluster CA Private Key", "Cluster CA private key readable. Forge any cluster certificate."),
    ("/etc/kubernetes/pki/apiserver.key", "API Server Private Key", "API server private key readable. Impersonate API server."),
    ("/etc/kubernetes/pki/etcd/server.key", "etcd Server Key", "etcd server key readable. Direct etcd access."),
    ("/root/.kube/config", "Root Kubeconfig", "Root kubeconfig readable. May contain cluster-admin credentials."),
    ("/root/.ssh/id_rsa", "Root SSH Private Key", "Root SSH private key readable. Lateral movement to other nodes."),
    ("/root/.ssh/id_ed25519", "Root SSH Private Key", "Root SSH ed25519 key readable. Lateral movement to other nodes."),
    ("/root/.ssh/authorized_keys", "Root SSH Authorized Keys", "Root authorized_keys readable. Identify trusted hosts."),
];

const WRITABLE_CHECKS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/etc/kubernetes",
    "/etc/kubernetes/pki",
];

// Dangerous Linux capabilities with exploitation context
const DANGEROUS_CAPS: &[(u8, &str, &str)] = &[
    (1, "CAP_DAC_OVERRIDE", "Bypass file write permissions. Write to any file on the filesystem."),
    (2, "CAP_DAC_READ_SEARCH", "Bypass file read permissions. Read any file including /etc/shadow."),
    (6, "CAP_SETGID", "Change process GID. Escalate to any group."),
    (7, "CAP_SETUID", "Change process UID. Escalate to root via setuid(0)."),
    (12, "CAP_NET_ADMIN", "Full network control. Sniff traffic, ARP spoof, modify routes."),
    (13, "CAP_NET_RAW", "Raw sockets. Network sniffing and packet injection."),
    (16, "CAP_SYS_MODULE", "Load/unload kernel modules. Kernel-level code execution."),
    (17, "CAP_SYS_RAWIO", "Raw I/O port access. Direct hardware manipulation."),
    (19, "CAP_SYS_PTRACE", "ptrace any process. Code injection into host processes via hostPID."),
    (21, "CAP_SYS_ADMIN", "Mount filesystems, namespace manipulation, cgroup escape. Primary container breakout vector."),
    (22, "CAP_SYS_BOOT", "Reboot the host system."),
    (27, "CAP_MKNOD", "Create device nodes. Access host block devices."),
    (38, "CAP_PERFMON", "Performance monitoring. Kernel-level side-channel attacks."),
    (39, "CAP_BPF", "Load eBPF programs. Kernel-level instrumentation and data exfiltration."),
];

pub fn detect_pod_context() -> PodContext {
    let mut ctx = PodContext::default();

    if Path::new(SA_TOKEN_PATH).exists() || std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        ctx.running_in_pod = true;
    } else {
        return ctx;
    }

    if Path::new(SA_TOKEN_PATH).exists() {
        ctx.sa_token_mounted = true;
        ctx.token_path = Some(SA_TOKEN_PATH.to_string());
    }

    if let Ok(ns) = std::fs::read_to_string(SA_NS_PATH) {
        ctx.sa_namespace = Some(ns.trim().to_string());
    }

    if Path::new(SA_CA_PATH).exists() {
        ctx.ca_cert_path = Some(SA_CA_PATH.to_string());
    }

    if let Ok(host) = std::env::var("KUBERNETES_SERVICE_HOST") {
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        ctx.api_server_env = Some(format!("https://{}:{}", host, port));
    }

    if let Some(token_path) = &ctx.token_path {
        if let Ok(token) = std::fs::read_to_string(token_path) {
            if let Some(payload) = decode_jwt_payload(&token) {
                if let Ok(claims) = serde_json::from_str::<serde_json::Value>(&payload) {
                    if let Some(sub) = claims.get("sub").and_then(|v| v.as_str()) {
                        if sub.starts_with("system:serviceaccount:") {
                            let parts: Vec<&str> = sub.splitn(4, ':').collect();
                            if parts.len() == 4 {
                                ctx.sa_namespace = Some(parts[2].to_string());
                                ctx.sa_name = Some(parts[3].to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Env var checks
    for (key, value) in std::env::vars() {
        if key.starts_with("KUBERNETES_") || key == "HOME" || key == "PATH" || key == "HOSTNAME" {
            continue;
        }
        let upper = key.to_uppercase();
        let mut matched_reason = None;

        for (exact, reason) in SENSITIVE_ENV_EXACT {
            if upper == *exact {
                matched_reason = Some(*reason);
                break;
            }
        }
        if matched_reason.is_none() {
            for (suffix, reason) in SENSITIVE_ENV_SUFFIXES {
                if upper.ends_with(suffix) {
                    matched_reason = Some(*reason);
                    break;
                }
            }
        }
        if let Some(reason) = matched_reason {
            let masked = if value.len() > 8 {
                format!("{}...{}", &value[..4], &value[value.len() - 4..])
            } else {
                "****".to_string()
            };
            ctx.interesting_env_vars.push(InterestingEnvVar {
                name: key,
                value: masked,
                reason: reason.to_string(),
            });
        }
    }

    // Host-only paths
    for (mount_path, mount_type, reason) in HOST_ONLY_PATHS {
        if Path::new(mount_path).exists() {
            ctx.interesting_mounts.push(InterestingMount {
                path: mount_path.to_string(),
                mount_type: mount_type.to_string(),
                reason: reason.to_string(),
            });
        }
    }

    // Sensitive files (only if readable)
    for (file_path, mount_type, reason) in SENSITIVE_FILE_CHECKS {
        if std::fs::read(file_path).is_ok() {
            ctx.interesting_mounts.push(InterestingMount {
                path: file_path.to_string(),
                mount_type: mount_type.to_string(),
                reason: reason.to_string(),
            });
        }
    }

    // Host PID namespace
    if is_host_pid_namespace() {
        ctx.interesting_mounts.push(InterestingMount {
            path: "/proc (host PID namespace)".to_string(),
            mount_type: "Host PID Namespace".to_string(),
            reason: "Sharing host PID namespace. Can see/ptrace host processes, read /proc/*/environ.".to_string(),
        });
    }

    // Writable checks
    for path in WRITABLE_CHECKS {
        if is_writable(path) {
            ctx.writable_paths.push(path.to_string());
        }
    }

    // === NEW: Linux capabilities ===
    ctx.capabilities = detect_capabilities();

    // === NEW: Container escape vectors ===
    ctx.escape_vectors = detect_escape_vectors();

    // === NEW: Cloud metadata (IMDS) ===
    ctx.cloud_metadata = detect_cloud_metadata();

    // === NEW: Network enumeration ===
    ctx.network_info = Some(enumerate_network());

    ctx
}

// ============================================================
// Linux Capabilities Detection
// ============================================================

fn detect_capabilities() -> Vec<CapabilityInfo> {
    let mut caps = Vec::new();

    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return caps,
    };

    let cap_eff = status
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .unwrap_or(0);

    if cap_eff == 0 {
        return caps;
    }

    let all_caps: u64 = 0x1FFFFFFFFFF; // bits 0-40
    if cap_eff & all_caps == all_caps {
        caps.push(CapabilityInfo {
            name: "ALL CAPABILITIES".to_string(),
            dangerous: true,
            reason: "Container has all Linux capabilities. Fully privileged, equivalent to root on host.".to_string(),
        });
        return caps;
    }

    for &(bit, name, reason) in DANGEROUS_CAPS {
        if cap_eff & (1u64 << bit) != 0 {
            caps.push(CapabilityInfo {
                name: name.to_string(),
                dangerous: true,
                reason: reason.to_string(),
            });
        }
    }

    caps
}

// ============================================================
// Container Escape Vector Detection
// ============================================================

fn detect_escape_vectors() -> Vec<EscapeVector> {
    let mut vectors = Vec::new();

    // Privileged mode: /sys/kernel/mm writable means we have full device access
    if is_writable("/sys/kernel/mm") {
        vectors.push(EscapeVector {
            vector_type: "Privileged Container".to_string(),
            path: "/sys/kernel/mm".to_string(),
            detail: "Container is privileged. Mount host filesystem: mkdir /mnt/host && mount /dev/sda1 /mnt/host".to_string(),
        });
    }

    // /proc/1/root accessible with real content (not our own root)
    if let Ok(entries) = std::fs::read_dir("/proc/1/root") {
        let count = entries.filter_map(|e| e.ok()).count();
        if count > 3 {
            // Check if PID 1 is a host process
            let is_host = std::fs::read_to_string("/proc/1/comm")
                .map(|c| {
                    let name = c.trim();
                    name == "systemd" || name == "init" || name == "launchd"
                })
                .unwrap_or(false);

            if is_host {
                vectors.push(EscapeVector {
                    vector_type: "Host Root Filesystem".to_string(),
                    path: "/proc/1/root".to_string(),
                    detail: "/proc/1/root exposes the host root filesystem. Read host files: cat /proc/1/root/etc/shadow".to_string(),
                });
            }
        }
    }

    // Common host mount paths
    for mount_path in &["/host", "/hostfs", "/rootfs", "/node-root"] {
        if Path::new(mount_path).is_dir() {
            // Verify it has real content (not empty mount)
            if let Ok(entries) = std::fs::read_dir(mount_path) {
                let count = entries.filter_map(|e| e.ok()).count();
                if count > 2 {
                    vectors.push(EscapeVector {
                        vector_type: "Host Filesystem Mount".to_string(),
                        path: mount_path.to_string(),
                        detail: format!("Host root filesystem mounted at {}. Access host files: ls {}/etc/shadow", mount_path, mount_path),
                    });
                }
            }
        }
    }

    // Running as root (UID 0)
    if is_running_as_root() {
        vectors.push(EscapeVector {
            vector_type: "Running as Root".to_string(),
            path: "uid=0".to_string(),
            detail: "Process runs as root (UID 0). Combined with capabilities or mounts, enables container escape.".to_string(),
        });
    }

    // Cgroup v1 release_agent escape path
    if let Some(agent_path) = find_writable_release_agent() {
        vectors.push(EscapeVector {
            vector_type: "Cgroup Release Agent".to_string(),
            path: agent_path,
            detail: "Cgroup release_agent is writable. Container escape via cgroup notify_on_release.".to_string(),
        });
    }

    // /proc/sysrq-trigger writable
    if is_writable("/proc/sysrq-trigger") {
        vectors.push(EscapeVector {
            vector_type: "SysRq Trigger".to_string(),
            path: "/proc/sysrq-trigger".to_string(),
            detail: "SysRq trigger writable. Can crash, reboot, or dump host memory.".to_string(),
        });
    }

    // Core pattern escape
    if is_writable("/proc/sys/kernel/core_pattern") {
        vectors.push(EscapeVector {
            vector_type: "Core Pattern Escape".to_string(),
            path: "/proc/sys/kernel/core_pattern".to_string(),
            detail: "core_pattern writable. Write |/path/to/payload to execute on host when a process crashes.".to_string(),
        });
    }

    vectors
}

fn find_writable_release_agent() -> Option<String> {
    let cgroup_root = Path::new("/sys/fs/cgroup");
    if !cgroup_root.is_dir() {
        return None;
    }
    let entries = std::fs::read_dir(cgroup_root).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        let agent = entry.path().join("release_agent");
        if agent.exists() && is_writable(agent.to_str().unwrap_or("")) {
            return Some(agent.to_string_lossy().to_string());
        }
    }
    None
}

// ============================================================
// Cloud Metadata (IMDS) Detection
// ============================================================

fn detect_cloud_metadata() -> Vec<CloudMetadataFinding> {
    let mut findings = Vec::new();

    // AWS IMDSv1
    if let Some(_body) = http_get("169.254.169.254:80", "/latest/meta-data/", "") {
        let mut detail = "AWS metadata service accessible (IMDSv1).".to_string();

        // Try to get IAM role
        if let Some(roles) = http_get(
            "169.254.169.254:80",
            "/latest/meta-data/iam/security-credentials/",
            "",
        ) {
            let role = roles.lines().next().unwrap_or("").trim();
            if !role.is_empty() {
                detail = format!(
                    "AWS metadata accessible. IAM role: {}. Get creds: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
                    role, role
                );
            }
        }

        findings.push(CloudMetadataFinding {
            provider: "AWS".to_string(),
            accessible: true,
            detail,
        });
    } else {
        // Check if IMDSv2 is enforced (PUT for token works but GET without token fails)
        if let Some(_) = http_put_token("169.254.169.254:80") {
            findings.push(CloudMetadataFinding {
                provider: "AWS".to_string(),
                accessible: true,
                detail: "AWS IMDSv2 detected (token required). PUT to /latest/api/token first, then GET with X-aws-ec2-metadata-token header.".to_string(),
            });
        }
    }

    // GCP
    if let Some(body) = http_get(
        "169.254.169.254:80",
        "/computeMetadata/v1/instance/service-accounts/default/email",
        "Metadata-Flavor: Google\r\n",
    ) {
        let detail = if body.contains("@") {
            format!("GCP metadata accessible. SA email: {}. Get token: curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", body.trim())
        } else {
            "GCP metadata accessible. Enumerate: curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/".to_string()
        };

        findings.push(CloudMetadataFinding {
            provider: "GCP".to_string(),
            accessible: true,
            detail,
        });
    }

    // Azure
    if let Some(_) = http_get(
        "169.254.169.254:80",
        "/metadata/instance?api-version=2021-02-01",
        "Metadata: true\r\n",
    ) {
        findings.push(CloudMetadataFinding {
            provider: "Azure".to_string(),
            accessible: true,
            detail: "Azure IMDS accessible. Get token: curl -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'".to_string(),
        });
    }

    findings
}

// ============================================================
// Network Enumeration
// ============================================================

fn enumerate_network() -> NetworkInfo {
    let mut info = NetworkInfo::default();

    // Network interfaces from /sys/class/net/
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" {
                info.interfaces.push(name);
            }
        }
    }
    info.interfaces.sort();

    // Listening ports from /proc/net/tcp
    parse_proc_net(&mut info, "/proc/net/tcp", "TCP");
    parse_proc_net(&mut info, "/proc/net/tcp6", "TCP6");

    info
}

fn parse_proc_net(info: &mut NetworkInfo, path: &str, protocol: &str) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        // State 0A = LISTEN
        if fields[3] != "0A" {
            continue;
        }

        let local = fields[1];
        let parts: Vec<&str> = local.split(':').collect();
        if parts.len() != 2 {
            continue;
        }

        let port = match u16::from_str_radix(parts[1], 16) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let address = if protocol == "TCP" {
            parse_hex_ipv4(parts[0])
        } else {
            parse_hex_ipv6(parts[0])
        };

        // Deduplicate
        if !info
            .listening_ports
            .iter()
            .any(|lp| lp.port == port && lp.protocol == protocol)
        {
            info.listening_ports.push(ListeningPort {
                port,
                address,
                protocol: protocol.to_string(),
            });
        }
    }
}

fn parse_hex_ipv4(hex: &str) -> String {
    if let Ok(n) = u32::from_str_radix(hex, 16) {
        format!(
            "{}.{}.{}.{}",
            n & 0xFF,
            (n >> 8) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 24) & 0xFF,
        )
    } else {
        "0.0.0.0".to_string()
    }
}

fn parse_hex_ipv6(hex: &str) -> String {
    if hex == "00000000000000000000000000000000" || hex == "00000000000000000000000001000000" {
        return "::".to_string();
    }
    if hex.len() == 32 {
        // Abbreviated display
        let mut parts = Vec::new();
        for i in (0..32).step_by(8) {
            let chunk = &hex[i..i + 8];
            if let Ok(n) = u32::from_str_radix(chunk, 16) {
                let swapped = n.swap_bytes();
                parts.push(format!("{:04x}:{:04x}", swapped >> 16, swapped & 0xFFFF));
            }
        }
        parts.join(":")
    } else {
        "::".to_string()
    }
}

// ============================================================
// HTTP helpers for IMDS
// ============================================================

fn http_get(addr: &str, path: &str, extra_headers: &str) -> Option<String> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;

    let stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(2),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;

    let host = addr.split(':').next().unwrap_or(addr);
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        path, host, extra_headers
    );

    let stream_ref = &stream;
    (&*stream_ref).write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    (&*stream_ref).read_to_end(&mut response).ok();
    let response = String::from_utf8_lossy(&response);

    let first_line = response.lines().next()?;
    if !first_line.contains("200") {
        return None;
    }

    if let Some(pos) = response.find("\r\n\r\n") {
        let body = response[pos + 4..].trim().to_string();
        if body.is_empty() {
            None
        } else {
            Some(body)
        }
    } else {
        None
    }
}

fn http_put_token(addr: &str) -> Option<String> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;

    let stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(2),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;

    let request = "PUT /latest/api/token HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\nConnection: close\r\n\r\n";

    let stream_ref = &stream;
    (&*stream_ref).write_all(request.as_bytes()).ok()?;

    let mut response = Vec::new();
    (&*stream_ref).read_to_end(&mut response).ok();
    let response = String::from_utf8_lossy(&response);

    let first_line = response.lines().next()?;
    if first_line.contains("200") {
        if let Some(pos) = response.find("\r\n\r\n") {
            return Some(response[pos + 4..].trim().to_string());
        }
    }
    None
}

// ============================================================
// Existing helpers
// ============================================================

fn decode_jwt_payload(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    use std::io::Read;
    let decoded = base64_decode(parts[1])?;
    let mut decoder = std::io::Cursor::new(decoded);
    let mut result = String::new();
    decoder.read_to_string(&mut result).ok()?;
    Some(result)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };

    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let url_safe = padded.replace('-', "+").replace('_', "/");

    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for byte in url_safe.bytes() {
        if byte == b'=' {
            break;
        }
        let val = table.iter().position(|&b| b == byte)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(output)
}

fn is_writable(path: &str) -> bool {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    use std::os::unix::fs::MetadataExt;
    let mode = metadata.mode();
    let file_uid = metadata.uid();
    let file_gid = metadata.gid();

    let our_uid = get_effective_uid();
    if our_uid == 0 {
        return true;
    }

    let our_gid = get_effective_gid();

    if our_uid == file_uid {
        return mode & 0o200 != 0;
    }
    if our_gid == file_gid {
        return mode & 0o020 != 0;
    }
    mode & 0o002 != 0
}

fn is_running_as_root() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Uid:") {
                let uid = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|u| u.parse::<u32>().ok())
                    .unwrap_or(u32::MAX);
                return uid == 0;
            }
        }
    }
    false
}

fn get_effective_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse().ok())
        })
        .unwrap_or(u32::MAX)
}

fn get_effective_gid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Gid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse().ok())
        })
        .unwrap_or(u32::MAX)
}

fn is_host_pid_namespace() -> bool {
    if let Ok(comm) = std::fs::read_to_string("/proc/1/comm") {
        let name = comm.trim();
        if name == "systemd" || name == "init" || name == "launchd" {
            return true;
        }
    }
    if let Ok(entries) = std::fs::read_dir("/proc") {
        let pid_count = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .count();
        if pid_count > 50 {
            return true;
        }
    }
    false
}
