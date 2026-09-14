use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use kube::Client;

use super::{EnvVar, PodInfo};

pub async fn enumerate_pods(client: &Client, namespace: &str) -> Result<Vec<PodInfo>> {
    let pod_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pods = pod_api.list(&ListParams::default()).await?;

    let mut results = Vec::new();

    for pod in pods.items {
        let metadata = &pod.metadata;
        let pod_name = metadata.name.clone().unwrap_or_default();
        let ns = metadata.namespace.clone().unwrap_or_default();

        let spec = match &pod.spec {
            Some(s) => s,
            None => continue,
        };

        let service_account = spec
            .service_account_name
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let host_pid = spec.host_pid.unwrap_or(false);
        let host_network = spec.host_network.unwrap_or(false);
        let automount = spec.automount_service_account_token.unwrap_or(true);
        let node_name = spec.node_name.clone();

        let mut host_path_mounts = Vec::new();
        if let Some(volumes) = &spec.volumes {
            for vol in volumes {
                if let Some(hp) = &vol.host_path {
                    host_path_mounts.push(hp.path.clone());
                }
            }
        }

        for container in &spec.containers {
            let mut privileged = false;
            if let Some(sc) = &container.security_context {
                privileged = sc.privileged.unwrap_or(false);
            }

            let mut env_vars = Vec::new();
            if let Some(envs) = &container.env {
                for env in envs {
                    let mut ev = EnvVar {
                        name: env.name.clone(),
                        value: env.value.clone(),
                        from_secret: None,
                        from_configmap: None,
                    };

                    if let Some(value_from) = &env.value_from {
                        if let Some(secret_ref) = &value_from.secret_key_ref {
                            ev.from_secret = Some(secret_ref.name.clone());
                        }
                        if let Some(cm_ref) = &value_from.config_map_key_ref {
                            ev.from_configmap = Some(cm_ref.name.clone());
                        }
                    }

                    env_vars.push(ev);
                }
            }

            results.push(PodInfo {
                name: pod_name.clone(),
                namespace: ns.clone(),
                service_account: service_account.clone(),
                node_name: node_name.clone(),
                privileged,
                host_pid,
                host_network,
                host_path_mounts: host_path_mounts.clone(),
                env_vars,
                image: container.image.clone().unwrap_or_default(),
                automount_sa_token: automount,
            });
        }
    }

    Ok(results)
}
