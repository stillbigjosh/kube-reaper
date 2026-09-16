use serde::Serialize;
use std::collections::HashSet;
use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug, Clone, Default, Serialize)]
pub struct DnsDiscoveryResults {
    pub dns_server: Option<String>,
    pub search_domains: Vec<String>,
    pub cluster_domain: Option<String>,
    pub discovered_services: Vec<DiscoveredService>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredService {
    pub name: String,
    pub namespace: String,
    pub cluster_ip: String,
    pub discovery_method: String,
}

const COMMON_SERVICES: &[&str] = &[
    "kubernetes",
    "kube-dns",
    "metrics-server",
    "kubernetes-dashboard",
    "dashboard",
    "ingress-nginx-controller",
    "traefik",
    "argocd-server",
    "argocd-repo-server",
    "gitea-http",
    "gitlab-webservice",
    "jenkins",
    "prometheus-server",
    "prometheus-kube-prometheus-prometheus",
    "grafana",
    "alertmanager",
    "vault",
    "vault-agent-injector-svc",
    "consul-server",
    "elasticsearch-master",
    "kibana",
    "redis-master",
    "mysql",
    "postgres",
    "postgresql",
    "mongodb",
    "rabbitmq",
    "kafka",
    "nats",
    "minio",
    "cert-manager",
    "cert-manager-webhook",
    "external-dns",
    "istiod",
    "istio-ingressgateway",
    "code-server",
    "registry",
    "harbor-core",
    "harbor-portal",
    "tekton-pipelines-controller",
    "kyverno-svc",
    "gatekeeper-webhook-service",
    "coredns",
    "etcd",
    "calico-typha",
    "cilium-agent",
    "linkerd-destination",
    "crossplane",
];

const WELL_KNOWN_NS: &[&str] = &[
    "default",
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "monitoring",
    "ingress-nginx",
    "cert-manager",
    "istio-system",
    "argocd",
    "flux-system",
    "tekton-pipelines",
    "metallb-system",
    "calico-system",
];

pub fn discover_services(known_namespaces: &[String]) -> DnsDiscoveryResults {
    let mut results = DnsDiscoveryResults::default();

    let resolv = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(c) => c,
        Err(_) => return results,
    };

    for line in resolv.lines() {
        let line = line.trim();
        if line.starts_with("nameserver") {
            if results.dns_server.is_none() {
                results.dns_server = line.split_whitespace().nth(1).map(|s| s.to_string());
            }
        } else if line.starts_with("search") {
            results.search_domains = line
                .split_whitespace()
                .skip(1)
                .map(|s| s.to_string())
                .collect();
        }
    }

    for domain in &results.search_domains {
        if let Some(pos) = domain.find(".svc.") {
            results.cluster_domain = Some(domain[pos + 5..].to_string());
            break;
        }
        if domain == "svc.cluster.local" {
            results.cluster_domain = Some("cluster.local".to_string());
            break;
        }
    }

    let dns_server = match &results.dns_server {
        Some(s) => s.clone(),
        None => return results,
    };

    let cluster_domain = results
        .cluster_domain
        .clone()
        .unwrap_or_else(|| "cluster.local".to_string());

    let mut all_ns: Vec<String> = known_namespaces.to_vec();
    for ns in WELL_KNOWN_NS {
        if !all_ns.iter().any(|n| n == ns) {
            all_ns.push(ns.to_string());
        }
    }
    for domain in &results.search_domains {
        let suffix = format!(".svc.{}", cluster_domain);
        if let Some(ns) = domain.strip_suffix(&suffix) {
            if !all_ns.iter().any(|n| n == ns) {
                all_ns.push(ns.to_string());
            }
        }
    }

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(150)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(150)));

    let dest = format!("{}:53", dns_server);
    let mut seen = HashSet::new();

    for ns in &all_ns {
        for svc_name in COMMON_SERVICES {
            let fqdn = format!("{}.{}.svc.{}", svc_name, ns, cluster_domain);
            if let Some(ip) = dns_resolve_a(&socket, &dest, &fqdn) {
                let key = format!("{}/{}", ns, svc_name);
                if seen.insert(key) {
                    results.discovered_services.push(DiscoveredService {
                        name: svc_name.to_string(),
                        namespace: ns.clone(),
                        cluster_ip: ip,
                        discovery_method: "DNS A lookup".to_string(),
                    });
                }
            }
        }
    }

    results
}

fn dns_resolve_a(socket: &UdpSocket, dest: &str, name: &str) -> Option<String> {
    let query = build_dns_query(name, 1);
    socket.send_to(&query, dest).ok()?;

    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    if len < 12 {
        return None;
    }

    let response = &buf[..len];

    let flags = u16::from_be_bytes([response[2], response[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return None;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]);
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    pos = skip_dns_name(response, pos)?;
    pos += 4; // QTYPE + QCLASS

    for _ in 0..ancount {
        if pos >= response.len() {
            break;
        }
        pos = skip_dns_name(response, pos)?;
        if pos + 10 > response.len() {
            break;
        }

        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= response.len() {
            return Some(format!(
                "{}.{}.{}.{}",
                response[pos],
                response[pos + 1],
                response[pos + 2],
                response[pos + 3]
            ));
        }

        pos += rdlength;
    }

    None
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    if pos >= data.len() {
        return None;
    }
    if data[pos] & 0xC0 == 0xC0 {
        return Some(pos + 2);
    }
    while pos < data.len() && data[pos] != 0 {
        if data[pos] & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += data[pos] as usize + 1;
    }
    Some(pos + 1)
}

fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    let id = name
        .bytes()
        .fold(0u16, |acc, b| acc.wrapping_add(b as u16))
        .wrapping_mul(31);
    buf.extend_from_slice(&id.to_be_bytes());

    buf.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);

    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    buf
}
