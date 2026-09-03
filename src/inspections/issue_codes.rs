//! Issue code registry: stable codes and short titles for report grouping.
//! 自定义问题代码体系（数字分区表示大类）：
//!   Node 001-005 | Pod 101-112 | Resource 201-205 | Network 301-305 |
//!   Storage 401-410 | Security 501-509 | Control plane 601-602 |
//!   Autoscaling 701-705 | Batch 801-805 | Policy 901-904 |
//!   Observability A01-A04 | Certificates B01-B03
//! issue 的 rule_id 使用纯编号（如 105、A01，数字分区表示大类），
//! 本注册表以编号为键；strip_prefix 保留用于兼容历史带前缀的数据。

/// Strips the category prefix from a rule id: "POD-105" -> "105", "OBS-A01" -> "A01".
/// Codes without a prefix are returned unchanged.
pub fn strip_prefix(code: &str) -> &str {
    code.rsplit_once('-').map(|(_, num)| num).unwrap_or(code)
}

/// Returns the short title for an issue code, or None if unknown.
pub fn short_title(code: &str) -> Option<&'static str> {
    match code {
        // Node
        "001" => Some("Node not ready"),
        "002" => Some("Node has resource pressure"),
        "003" => Some("Zombie processes on node"),
        "004" => Some("Node disk usage high (Warning)"),
        "005" => Some("Node disk usage critical"),
        // Pod
        "101" => Some("Pod in Failed state"),
        "102" => Some("Pod cannot be scheduled"),
        "103" => Some("Container restart count too high"),
        "104" => Some("Container in abnormal state"),
        "105" => Some("ImagePullBackOff"),
        "106" => Some("ErrImagePull"),
        "107" => Some("CrashLoopBackOff"),
        "108" => Some("ContainerCreating"),
        "109" => Some("CreateContainerConfigError"),
        "110" => Some("OOMKilled"),
        "111" => Some("Container terminated (non-zero exit)"),
        "112" => Some("Pod Running but not Ready"),
        // Resource
        "201" => Some("Container has no resource requests"),
        "202" => Some("Container has no resource limits"),
        "203" => Some("Namespace has no resource quota"),
        "204" => Some("CPU limit below request"),
        "205" => Some("Memory limit below request"),
        // Network
        "301" => Some("LoadBalancer has no external IP"),
        "302" => Some("NodePort outside recommended range"),
        "303" => Some("Service has no selector or endpoints"),
        "304" => Some("DNS deployment not ready"),
        "305" => Some("DNS service not found"),
        // Storage
        "401" => Some("PV config or backing storage issue"),
        "402" => Some("PV Released, needs cleanup"),
        "403" => Some("PV Retained, manual action needed"),
        "404" => Some("PV has no reclaim policy"),
        "405" => Some("PVC storage class or capacity issue"),
        "406" => Some("PVC has data loss risk"),
        "407" => Some("PVC has no storage class"),
        "408" => Some("StorageClass has no provisioner"),
        "409" => Some("No default StorageClass"),
        "410" => Some("Multiple StorageClasses marked default"),
        // Security
        "501" => Some("ClusterRole has excessive permissions"),
        "502" => Some("User has cluster-admin"),
        "503" => Some("ServiceAccount has cluster-admin"),
        "504" => Some("Pod runs as root"),
        "505" => Some("Container runs privileged"),
        "506" => Some("Container runs as root"),
        "507" => Some("Container allows privilege escalation"),
        "508" => Some("Insufficient network policy coverage"),
        "509" => Some("Uses default ServiceAccount"),
        // Control plane
        "601" => Some("Control plane component not ready"),
        "602" => Some("Static Pod not ready"),
        // Autoscaling
        "701" => Some("HPA replica range too narrow"),
        "702" => Some("HPA has no metrics configured"),
        "703" => Some("HPA target workload or metrics issue"),
        "704" => Some("HPA behavior limits scaling"),
        "705" => Some("HPA metric target not configured"),
        // Batch
        "801" => Some("CronJob suspended"),
        "802" => Some("CronJob job failed"),
        "803" => Some("CronJob schedule or controller issue"),
        "804" => Some("Job needs backoffLimit or resource check"),
        "805" => Some("Job Pod stuck or timeout adjustment needed"),
        // Policy
        "901" => Some("No ResourceQuota configured"),
        "902" => Some("No LimitRange configured"),
        "903" => Some("Critical workload has no PDB"),
        "904" => Some("Replica count does not satisfy PDB"),
        // Observability
        "A01" => Some("metrics-server not deployed"),
        "A02" => Some("kube-state-metrics not deployed"),
        "A03" => Some("Log aggregation not deployed"),
        "A04" => Some("Prometheus/monitoring not deployed"),
        // Certificates
        "B01" => Some("CSR long Pending or abnormal"),
        "B02" => Some("Certificate expiring soon"),
        "B03" => Some("Certificate expired"),
        _ => None,
    }
}

/// Returns the Chinese short title for an issue code, or None if unknown.
/// Used when the report language is Chinese (`--lang zh`, the default).
pub fn short_title_zh(code: &str) -> Option<&'static str> {
    match code {
        // Node
        "001" => Some("节点未就绪"),
        "002" => Some("节点存在资源压力"),
        "003" => Some("节点存在僵尸进程"),
        "004" => Some("节点磁盘使用率过高（警告）"),
        "005" => Some("节点磁盘使用率严重"),
        // Pod
        "101" => Some("Pod 处于失败状态"),
        "102" => Some("Pod 无法调度"),
        "103" => Some("容器重启次数过高"),
        "104" => Some("容器处于异常状态"),
        "105" => Some("镜像拉取失败（ImagePullBackOff）"),
        "106" => Some("镜像拉取错误（ErrImagePull）"),
        "107" => Some("崩溃循环（CrashLoopBackOff）"),
        "108" => Some("容器创建中"),
        "109" => Some("创建容器配置错误"),
        "110" => Some("OOM 被杀"),
        "111" => Some("容器已终止（非零退出码）"),
        "112" => Some("Pod 运行中但未就绪"),
        // Resource
        "201" => Some("容器未设置资源请求"),
        "202" => Some("容器未设置资源限制"),
        "203" => Some("命名空间未设置资源配额"),
        "204" => Some("CPU 限制低于请求"),
        "205" => Some("内存限制低于请求"),
        // Network
        "301" => Some("负载均衡器无外部 IP"),
        "302" => Some("NodePort 超出推荐范围"),
        "303" => Some("服务无选择器或端点"),
        "304" => Some("DNS 部署未就绪"),
        "305" => Some("DNS 服务未找到"),
        // Storage
        "401" => Some("PV 配置或后端存储问题"),
        "402" => Some("PV 处于 Released，需要清理"),
        "403" => Some("PV 处于 Retained，需要手动处理"),
        "404" => Some("PV 未设置回收策略"),
        "405" => Some("PVC 存储类或容量问题"),
        "406" => Some("PVC 存在数据丢失风险"),
        "407" => Some("PVC 未指定存储类"),
        "408" => Some("StorageClass 未配置供应器"),
        "409" => Some("没有默认 StorageClass"),
        "410" => Some("多个 StorageClass 被标记为默认"),
        // Security
        "501" => Some("ClusterRole 权限过大"),
        "502" => Some("用户具有 cluster-admin 权限"),
        "503" => Some("ServiceAccount 具有 cluster-admin 权限"),
        "504" => Some("Pod 以 root 用户运行"),
        "505" => Some("容器以特权模式运行"),
        "506" => Some("容器以 root 用户运行"),
        "507" => Some("容器允许权限提升"),
        "508" => Some("网络策略覆盖不足"),
        "509" => Some("使用默认 ServiceAccount"),
        // Control plane
        "601" => Some("控制平面组件未就绪"),
        "602" => Some("静态 Pod 未就绪"),
        // Autoscaling
        "701" => Some("HPA 副本范围过窄"),
        "702" => Some("HPA 未配置指标"),
        "703" => Some("HPA 目标工作负载或指标问题"),
        "704" => Some("HPA 行为限制伸缩"),
        "705" => Some("HPA 指标目标未配置"),
        // Batch
        "801" => Some("CronJob 被挂起"),
        "802" => Some("CronJob 任务失败"),
        "803" => Some("CronJob 调度或控制器问题"),
        "804" => Some("Job 需要 backoffLimit 或资源检查"),
        "805" => Some("Job Pod 卡住或需要调整超时"),
        // Policy
        "901" => Some("未配置 ResourceQuota"),
        "902" => Some("未配置 LimitRange"),
        "903" => Some("关键工作负载没有 PDB"),
        "904" => Some("副本数不满足 PDB"),
        // Observability
        "A01" => Some("未部署 metrics-server"),
        "A02" => Some("未部署 kube-state-metrics"),
        "A03" => Some("未部署日志聚合"),
        "A04" => Some("未部署 Prometheus/监控"),
        // Certificates
        "B01" => Some("CSR 长时间 Pending 或异常"),
        "B02" => Some("证书即将过期"),
        "B03" => Some("证书已过期"),
        _ => None,
    }
}
