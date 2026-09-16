use k8s_openapi::api::core::v1::{
    Capabilities, Container, HostPathVolumeSource, Pod, PodSpec, SecurityContext, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use kube::Api;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NamespaceAdmissionResult {
    pub namespace: String,
    pub can_create_pods: bool,
    pub probes: Vec<AdmissionProbe>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionProbe {
    pub probe_type: String,
    pub allowed: bool,
    pub detail: String,
}

const PROBE_IMAGE: &str = "busybox:latest";
const PROBE_PREFIX: &str = "kr-probe";

pub async fn probe_namespace(
    client: &kube::Client,
    namespace: &str,
) -> NamespaceAdmissionResult {
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pp = PostParams {
        dry_run: true,
        ..Default::default()
    };

    let baseline = build_pod(namespace, "baseline", None, None);
    match api.create(&pp, &baseline).await {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("cannot create") || msg.contains("forbidden") || msg.contains("unauthorized") {
                return NamespaceAdmissionResult {
                    namespace: namespace.to_string(),
                    can_create_pods: false,
                    probes: Vec::new(),
                };
            }
        }
    }

    let probes = vec![
        ("privileged", build_privileged_pod(namespace)),
        ("hostPID", build_hostpid_pod(namespace)),
        ("hostNetwork", build_hostnet_pod(namespace)),
        ("hostPath", build_hostpath_pod(namespace)),
        ("CAP_SYS_ADMIN", build_capsysadmin_pod(namespace)),
        ("runAsRoot", build_runasroot_pod(namespace)),
    ];

    let mut results = Vec::new();
    for (probe_type, pod) in probes {
        results.push(run_probe(&api, &pp, probe_type, pod).await);
    }

    NamespaceAdmissionResult {
        namespace: namespace.to_string(),
        can_create_pods: true,
        probes: results,
    }
}

async fn run_probe(api: &Api<Pod>, pp: &PostParams, probe_type: &str, pod: Pod) -> AdmissionProbe {
    match api.create(pp, &pod).await {
        Ok(_) => AdmissionProbe {
            probe_type: probe_type.to_string(),
            allowed: true,
            detail: "Allowed by admission controller".to_string(),
        },
        Err(e) => {
            let msg = e.to_string();
            let detail = extract_rejection_detail(&msg);
            AdmissionProbe {
                probe_type: probe_type.to_string(),
                allowed: false,
                detail,
            }
        }
    }
}

fn extract_rejection_detail(msg: &str) -> String {
    if let Some(pos) = msg.find("PodSecurity") {
        let segment = &msg[pos..];
        segment.chars().take(200).collect()
    } else if let Some(pos) = msg.find("admission webhook") {
        let segment = &msg[pos..];
        segment.chars().take(200).collect()
    } else if let Some(pos) = msg.find("denied") {
        let start = if pos > 20 { pos - 20 } else { 0 };
        let segment = &msg[start..];
        segment.chars().take(200).collect()
    } else {
        msg.chars().take(200).collect::<String>()
    }
}

fn base_container() -> Container {
    Container {
        name: "probe".to_string(),
        image: Some(PROBE_IMAGE.to_string()),
        command: Some(vec!["true".to_string()]),
        ..Default::default()
    }
}

fn build_pod(
    ns: &str,
    suffix: &str,
    spec_override: Option<Box<dyn FnOnce(&mut PodSpec)>>,
    container_override: Option<Box<dyn FnOnce(&mut Container)>>,
) -> Pod {
    let mut container = base_container();
    if let Some(f) = container_override {
        f(&mut container);
    }

    let mut spec = PodSpec {
        containers: vec![container],
        restart_policy: Some("Never".to_string()),
        ..Default::default()
    };
    if let Some(f) = spec_override {
        f(&mut spec);
    }

    Pod {
        metadata: ObjectMeta {
            name: Some(format!("{}-{}", PROBE_PREFIX, suffix)),
            namespace: Some(ns.to_string()),
            ..Default::default()
        },
        spec: Some(spec),
        ..Default::default()
    }
}

fn build_privileged_pod(ns: &str) -> Pod {
    build_pod(
        ns,
        "priv",
        None,
        Some(Box::new(|c: &mut Container| {
            c.security_context = Some(SecurityContext {
                privileged: Some(true),
                ..Default::default()
            });
        })),
    )
}

fn build_hostpid_pod(ns: &str) -> Pod {
    build_pod(
        ns,
        "hpid",
        Some(Box::new(|s: &mut PodSpec| {
            s.host_pid = Some(true);
        })),
        None,
    )
}

fn build_hostnet_pod(ns: &str) -> Pod {
    build_pod(
        ns,
        "hnet",
        Some(Box::new(|s: &mut PodSpec| {
            s.host_network = Some(true);
        })),
        None,
    )
}

fn build_hostpath_pod(ns: &str) -> Pod {
    build_pod(
        ns,
        "hpath",
        Some(Box::new(|s: &mut PodSpec| {
            s.volumes = Some(vec![Volume {
                name: "hostroot".to_string(),
                host_path: Some(HostPathVolumeSource {
                    path: "/".to_string(),
                    type_: Some("Directory".to_string()),
                }),
                ..Default::default()
            }]);
        })),
        Some(Box::new(|c: &mut Container| {
            c.volume_mounts = Some(vec![VolumeMount {
                name: "hostroot".to_string(),
                mount_path: "/host".to_string(),
                ..Default::default()
            }]);
        })),
    )
}

fn build_capsysadmin_pod(ns: &str) -> Pod {
    build_pod(
        ns,
        "cap",
        None,
        Some(Box::new(|c: &mut Container| {
            c.security_context = Some(SecurityContext {
                capabilities: Some(Capabilities {
                    add: Some(vec!["SYS_ADMIN".to_string()]),
                    ..Default::default()
                }),
                ..Default::default()
            });
        })),
    )
}

fn build_runasroot_pod(ns: &str) -> Pod {
    build_pod(
        ns,
        "root",
        None,
        Some(Box::new(|c: &mut Container| {
            c.security_context = Some(SecurityContext {
                run_as_user: Some(0),
                ..Default::default()
            });
        })),
    )
}
