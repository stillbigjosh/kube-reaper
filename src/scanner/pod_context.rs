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

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SA_NS_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const SA_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

// Env var names that ARE credentials (exact match or strong suffix)
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

// Env var suffixes that indicate actual credential values
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

// Paths that never exist in a normal container, only via explicit host mount
const HOST_ONLY_PATHS: &[(&str, &str, &str)] = &[
    ("/var/run/docker.sock", "Docker Socket", "Docker socket mounted. Container escape via docker commands."),
    ("/run/containerd/containerd.sock", "Containerd Socket", "Containerd socket mounted. Container escape via ctr/crictl."),
    ("/var/run/crio/crio.sock", "CRI-O Socket", "CRI-O socket mounted. Container escape via crictl."),
];

// Specific files that prove host access if they exist AND are readable
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

// Writable paths that actually matter (not /tmp which is always writable)
const WRITABLE_CHECKS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/etc/kubernetes",
    "/etc/kubernetes/pki",
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

    // Env var checks: exact matches and strong suffixes only
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

    // Host-only paths: if these exist, something was mounted
    for (mount_path, mount_type, reason) in HOST_ONLY_PATHS {
        if Path::new(mount_path).exists() {
            ctx.interesting_mounts.push(InterestingMount {
                path: mount_path.to_string(),
                mount_type: mount_type.to_string(),
                reason: reason.to_string(),
            });
        }
    }

    // Sensitive files: only flag if we can actually read the content
    for (file_path, mount_type, reason) in SENSITIVE_FILE_CHECKS {
        if std::fs::read(file_path).is_ok() {
            ctx.interesting_mounts.push(InterestingMount {
                path: file_path.to_string(),
                mount_type: mount_type.to_string(),
                reason: reason.to_string(),
            });
        }
    }

    // Host PID namespace detection
    if is_host_pid_namespace() {
        ctx.interesting_mounts.push(InterestingMount {
            path: "/proc (host PID namespace)".to_string(),
            mount_type: "Host PID Namespace".to_string(),
            reason: "Sharing host PID namespace. Can see/ptrace host processes, read /proc/*/environ.".to_string(),
        });
    }

    for path in WRITABLE_CHECKS {
        if is_writable(path) {
            ctx.writable_paths.push(path.to_string());
        }
    }

    ctx
}

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
    use std::fs;
    if let Ok(metadata) = fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        mode & 0o222 != 0
    } else {
        false
    }
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
