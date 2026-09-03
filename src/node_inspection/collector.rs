//! 节点采集的 K8s API 辅助逻辑：按节点聚合容器状态计数（pod_ip 采集后填充）。

use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;
use kube::Api;
use log::debug;
use std::collections::HashMap;

use crate::k8s::K8sClient;
use crate::node_inspection::NodeInspectionResult;

/// Lists all pods cluster-wide, aggregates container states per node, and sets container_state_counts on each result.
pub async fn fill_container_state_counts(client: &K8sClient, results: &mut [NodeInspectionResult]) {
    let pods_api: Api<Pod> = client.pods(None);
    let list_params = ListParams::default();
    let all_pods = match pods_api.list(&list_params).await {
        Ok(l) => l,
        Err(e) => {
            debug!("List all pods for container state counts failed: {}", e);
            return;
        }
    };

    // node_name -> (running, waiting, exited)
    let mut per_node: HashMap<String, (u32, u32, u32)> = HashMap::new();
    for pod in all_pods.items {
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|s| s.node_name.as_deref())
            .unwrap_or("");
        if node_name.is_empty() {
            continue;
        }
        let status = match &pod.status {
            Some(s) => s,
            None => continue,
        };
        let init = status.init_container_statuses.as_deref().unwrap_or(&[]);
        let main = status.container_statuses.as_deref().unwrap_or(&[]);
        for cs in init.iter().chain(main.iter()) {
            let entry = per_node.entry(node_name.to_string()).or_insert((0, 0, 0));
            if let Some(ref state) = cs.state {
                if state.running.is_some() {
                    entry.0 += 1;
                } else if state.waiting.is_some() {
                    entry.1 += 1;
                } else if state.terminated.is_some() {
                    entry.2 += 1;
                } else {
                    entry.1 += 1; // default waiting
                }
            }
        }
    }

    for result in results.iter_mut() {
        if let Some(&(running, waiting, exited)) = per_node.get(&result.node_name) {
            let mut counts = HashMap::new();
            if running > 0 {
                counts.insert("running".to_string(), running);
            }
            if exited > 0 {
                counts.insert("exited".to_string(), exited);
            }
            if waiting > 0 {
                counts.insert("waiting".to_string(), waiting);
            }
            if !counts.is_empty() {
                result.container_state_counts = Some(counts);
            }
        }
    }
}
