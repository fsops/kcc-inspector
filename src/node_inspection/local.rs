//! 节点本机巡检采集（Rust 实现，迁移自 node-check-universal.sh）。
//! 在 DaemonSet 中运行时，宿主机根目录被只读挂载到 `KCC_HOST_ROOT`（默认 /host），
//! 读取 `/host/proc`、`/host/sys`、`/host/etc` 获得宿主视角数据。
//! 该模块不依赖网络，直接返回与 NodeInspectionResult schema 一致的 JSON。

use crate::node_inspection::types::{
    NodeCertificate, NodeDiskMount, NodeInspectionResult, NodeKernel, NodeResources, NodeSecurity,
    NodeServices, NodeStability,
};
use chrono::{Local, Utc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 进程名 → 对应服务的开关字段
const SERVICE_PROCESSES: &[(&str, ServiceKind)] = &[
    ("chronyd", ServiceKind::Ntp),
    ("ntpd", ServiceKind::Ntp),
    ("systemd-timesyncd", ServiceKind::Ntp),
    ("systemd-journald", ServiceKind::Journald),
    ("crond", ServiceKind::Crontab),
    ("kubelet", ServiceKind::Kubelet),
    ("containerd", ServiceKind::Runtime),
    ("dockerd", ServiceKind::Runtime),
    ("crio", ServiceKind::Runtime),
];

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ServiceKind {
    Ntp,
    Journald,
    Crontab,
    Kubelet,
    Runtime,
}

#[derive(Clone)]
pub struct LocalCollector {
    root: PathBuf,
    node_name: String,
}

impl LocalCollector {
    /// 使用环境变量 KCC_HOST_ROOT（默认 /host）与 NODE_NAME 创建采集器。
    pub fn from_env() -> Self {
        let root = std::env::var("KCC_HOST_ROOT").unwrap_or_else(|_| "/host".to_string());
        let node_name = std::env::var("NODE_NAME").unwrap_or_else(|_| hostname_fallback(&root));

        Self {
            root: PathBuf::from(root),
            node_name,
        }
    }

    /// 返回节点名（轻量读取，不触发完整采集）。
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    fn proc(&self) -> PathBuf {
        self.root.join("proc")
    }
    fn sys(&self) -> PathBuf {
        self.root.join("sys")
    }
    fn etc(&self) -> PathBuf {
        self.root.join("etc")
    }

    pub fn collect(&self) -> NodeInspectionResult {
        let os_version = self.read_os_version();
        let kernel_version = self.read_string(&self.proc().join("sys/kernel/osrelease"));
        let uptime = self.read_uptime();
        let resources = self.gather_resources();
        let disk_mounts = self.gather_disk_mounts();
        let container_states_json = HashMap::new(); // 由主程序通过 K8s API 填充
        let services = self.gather_services();
        let security = self.gather_security();
        let stability = self.gather_stability();
        let kernel = self.gather_kernel();
        let zombie_count = self.count_zombie_processes();
        let issue_count =
            compute_issue_count(&resources, &services, &security, &kernel, zombie_count);
        let node_certificates = self.collect_certificates();

        NodeInspectionResult {
            node_name: self.node_name.clone(),
            hostname: self.node_name.clone(),
            timestamp: Utc::now().to_rfc3339(),
            timestamp_local: Some(Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string()),
            runtime: String::new(),
            os_version,
            kernel_version,
            uptime,
            resources,
            container_state_counts: Some(container_states_json),
            services,
            security,
            stability: Some(stability),
            kernel,
            zombie_count: Some(zombie_count),
            issue_count,
            node_certificates: if node_certificates.is_empty() {
                None
            } else {
                Some(node_certificates)
            },
            node_disks: if disk_mounts.is_empty() {
                None
            } else {
                Some(disk_mounts)
            },
        }
    }

    // ---------- 读取辅助 ----------
    fn read_string(&self, p: &Path) -> Option<String> {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn read_os_version(&self) -> Option<String> {
        let candidates = [
            self.etc().join("os-release"),
            self.root.join("usr/lib/os-release"),
        ];
        for c in candidates.iter() {
            if let Ok(content) = std::fs::read_to_string(c) {
                for line in content.lines() {
                    if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                        return Some(v.trim_matches('"').chars().take(200).collect());
                    }
                }
            }
        }
        None
    }

    fn read_uptime(&self) -> Option<String> {
        let s = self.read_string(&self.proc().join("uptime"))?;
        let secs: f64 = s.split_whitespace().next()?.parse().ok()?;
        Some(format_duration(secs as u64))
    }

    fn gather_resources(&self) -> NodeResources {
        let cpu_cores = self
            .read_string(&self.proc().join("cpuinfo"))
            .map(|s| s.lines().filter(|l| l.starts_with("processor")).count() as u32)
            .filter(|c| *c > 0);

        let (cpu_used_pct, cpu_used) = self.cpu_usage_sample();

        let meminfo = self.read_string(&self.proc().join("meminfo"));
        let mem_total_kb = meminfo_field(&meminfo, "MemTotal");
        let mem_avail_kb =
            meminfo_field(&meminfo, "MemAvailable").or_else(|| meminfo_field(&meminfo, "MemFree"));
        let (_mem_used_kb, mem_total_mib, mem_used_mib, mem_used_pct) =
            match (mem_total_kb, mem_avail_kb) {
                (Some(total), Some(avail)) => {
                    let used = total.saturating_sub(avail);
                    let pct = if total > 0 {
                        used as f64 / total as f64 * 100.0
                    } else {
                        0.0
                    };
                    (Some(used), Some(total / 1024), Some(used / 1024), Some(pct))
                }
                _ => (None, None, None, None),
            };

        // 磁盘（宿主机根）
        let root_path = if self.root.exists() {
            &self.root
        } else {
            Path::new("/")
        };
        let (disk_total_g, disk_used_g, disk_used_pct, root_pct) = disk_usage(root_path);

        let load = self
            .read_string(&self.proc().join("loadavg"))
            .unwrap_or_default();
        let load_parts: Vec<String> = load.split_whitespace().map(|s| s.to_string()).collect();
        let (l1, l5, l15) = (
            load_parts.first().cloned(),
            load_parts.get(1).cloned(),
            load_parts.get(2).cloned(),
        );

        let swap = self.gather_swap();

        let mut status = "ok".to_string();
        let mut detail = String::new();
        if cpu_cores.is_none() {
            status = "error".to_string();
            detail = "cpu cores unknown".to_string();
        }
        if mem_total_mib.is_none() {
            status = "error".to_string();
            detail = if detail.is_empty() {
                "memory unknown".to_string()
            } else {
                format!("{}; memory unknown", detail)
            };
        }

        NodeResources {
            cpu_cores,
            cpu_used,
            cpu_used_pct,
            memory_total_mib: mem_total_mib,
            memory_used_mib: mem_used_mib,
            memory_used_pct: mem_used_pct,
            root_disk_pct: root_pct,
            disk_total_g,
            disk_used_g,
            disk_used_pct,
            load_1m: l1,
            load_5m: l5,
            load_15m: l15,
            swap_enabled: swap.0,
            swap_total_g: swap.1,
            swap_used_g: swap.2,
            swap_used_pct: swap.3,
            status,
            detail,
        }
    }

    fn cpu_usage_sample(&self) -> (Option<f64>, Option<f64>) {
        let stat_path = self.proc().join("stat");
        let s1 = match self.read_string(&stat_path) {
            Some(s) => s,
            None => return (None, None),
        };
        let (t1, id1) = cpu_line_idle(&s1);
        std::thread::sleep(Duration::from_millis(1000));
        let s2 = match self.read_string(&stat_path) {
            Some(s) => s,
            None => return (None, None),
        };
        let (t2, id2) = cpu_line_idle(&s2);
        let (Some(t1), Some(id1), Some(t2), Some(id2)) = (t1, id1, t2, id2) else {
            return (None, None);
        };
        let td = (t2 - t1) as i64;
        if td <= 0 {
            return (None, None);
        }
        let idle = (id2 - id1) as i64;
        let pct = (1.0 - idle as f64 / td as f64) * 100.0;
        (Some(pct), None)
    }

    fn gather_swap(&self) -> (Option<bool>, Option<f64>, Option<f64>, Option<f64>) {
        let meminfo = self.read_string(&self.proc().join("meminfo"));
        let total_kb = meminfo_field(&meminfo, "SwapTotal").unwrap_or(0);
        let free_kb = meminfo_field(&meminfo, "SwapFree").unwrap_or(0);
        let used_kb = total_kb.saturating_sub(free_kb);
        let enabled = if total_kb > 0 {
            Some(true)
        } else {
            Some(false)
        };
        let total_g = if total_kb > 0 {
            Some(total_kb as f64 / 1024.0 / 1024.0)
        } else {
            Some(0.0)
        };
        let used_g = if total_kb > 0 {
            Some(used_kb as f64 / 1024.0 / 1024.0)
        } else {
            Some(0.0)
        };
        let pct = if total_kb > 0 {
            Some(used_kb as f64 / total_kb as f64 * 100.0)
        } else {
            Some(0.0)
        };
        (enabled, total_g, used_g, pct)
    }

    fn gather_disk_mounts(&self) -> Vec<NodeDiskMount> {
        // 解析挂载表。DaemonSet 把宿主机根目录递归绑定挂载到 KCC_HOST_ROOT（默认 /host），
        // 因此挂载表内容取决于容器运行时如何提供 /proc，存在两种视图：
        //   1) 容器视角（本项目清单的默认形态）：宿主机挂载以 /host 前缀出现
        //      （/host、/host/data、/host/boot...），容器自身挂载（overlay /、proc、shm）不带前缀；
        //   2) 宿主视角（额外把宿主机 /proc 挂载进容器时）：条目本身就是宿主机路径（/、/data、/boot）。
        // 下面先自动识别视图，再把挂载点统一归一化为宿主机路径。
        let mounts = match self.read_string(&self.proc().join("mounts")) {
            Some(s) => s,
            None => return Vec::new(),
        };
        // 视图检测：挂载表中存在 /host 或 /host/... 条目 → 容器视角，需去掉 /host 前缀
        let pod_view = mounts.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 2 && (parts[1] == "/host" || parts[1].starts_with("/host/"))
        });
        // 排除容器运行时/系统数据目录等噪音，保持磁盘清单聚焦在真实数据目录
        const NOISE_DIRS: [&str; 6] = [
            "/var/lib/containerd",
            "/var/lib/docker",
            "/var/lib/etcd",
            "/var/lib/cni",
            "/run/containerd",
            "/run/user",
        ];
        // kubelet 下仅保留 local-volume（真实块设备数据卷），
        // 排除 projected/secret/empty-dir/configmap 等临时卷及其子路径
        const KUBELET_PODS: &str = "/var/lib/kubelet/pods";
        const LOCAL_VOLUME: &str = "kubernetes.io~local-volume";
        const VOLUME_SUBPATH: &str = "/volume-subpaths/";

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut out = Vec::new();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let (device, mount, fstype) = (
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].to_string(),
            );
            // 归一化为宿主机路径：容器视角下剥掉 /host 前缀并跳过容器自身挂载；
            // 宿主视角下路径本身就是宿主机路径，直接使用
            let host_mount: String = if pod_view {
                if mount == "/host" {
                    "/".to_string()
                } else if let Some(rest) = mount.strip_prefix("/host/") {
                    // 还原为以 / 开头的宿主机绝对路径（/host/boot -> /boot）
                    format!("/{}", rest)
                } else {
                    continue;
                }
            } else {
                mount.clone()
            };
            // 排除噪音目录
            if NOISE_DIRS.iter().any(|d| host_mount.starts_with(d)) {
                continue;
            }
            // kubelet 下只保留 local-volume，排除临时卷和子路径
            if host_mount.starts_with(KUBELET_PODS)
                && (!host_mount.contains(LOCAL_VOLUME) || host_mount.contains(VOLUME_SUBPATH))
            {
                continue;
            }
            if seen.contains(&host_mount) {
                continue;
            }
            seen.insert(host_mount.clone());
            // 统计容量：mapped_path 把宿主机路径映射回容器内路径（/data -> /host/data）
            if let (Some(total_g), Some(used_g), Some(pct), _) =
                disk_usage(&self.mapped_path(&host_mount))
            {
                // 设备过滤：根目录始终保留；真实块设备（物理磁盘）保留；tmpfs 等内存盘不展示
                let is_root = host_mount == "/";
                let is_block = device.starts_with("/dev/");
                if !is_root && !is_block {
                    continue;
                }
                out.push(NodeDiskMount {
                    device,
                    mount_point: host_mount,
                    fstype,
                    total_g: Some(total_g),
                    used_g: Some(used_g),
                    used_pct: Some(pct),
                });
            }
        }
        out
    }

    /// 把宿主机挂载点映射为容器内可访问路径（/ -> /host）
    fn mapped_path(&self, mount: &str) -> PathBuf {
        if mount == "/" {
            self.root.clone()
        } else {
            self.root.join(mount.trim_start_matches('/'))
        }
    }

    fn gather_services(&self) -> NodeServices {
        let present = self.scan_cmdline_contains();
        let mut ntp = false;
        let mut journald = false;
        let mut crontab = false;
        let mut kubelet = false;
        let mut runtime = false;
        for (name, kind) in SERVICE_PROCESSES {
            if present.iter().any(|p| p.contains(name)) {
                match kind {
                    ServiceKind::Ntp => ntp = true,
                    ServiceKind::Journald => journald = true,
                    ServiceKind::Crontab => crontab = true,
                    ServiceKind::Kubelet => kubelet = true,
                    ServiceKind::Runtime => runtime = true,
                }
            }
        }
        NodeServices {
            runtime: String::new(),
            journald_active: Some(journald),
            crontab_present: Some(crontab),
            ntp_synced: Some(ntp),
            kubelet_running: Some(kubelet),
            container_runtime_running: Some(runtime),
            status: "ok".to_string(),
            detail: String::new(),
        }
    }

    fn gather_security(&self) -> NodeSecurity {
        let selinux = self.read_selinux();
        let modules = self
            .read_string(&self.proc().join("modules"))
            .unwrap_or_default();
        let ipvs = modules.lines().any(|l| l.starts_with("ip_vs"));
        let br_netfilter = modules.lines().any(|l| l.starts_with("br_netfilter"));
        let overlay = modules
            .lines()
            .any(|l| l.starts_with("overlay") || l.starts_with("overlayfs"));
        let nf_conntrack = modules.lines().any(|l| l.starts_with("nf_conntrack"));
        let (nf_count, nf_max) = if nf_conntrack {
            (
                self.read_string(&self.proc().join("sys/net/netfilter/nf_conntrack_count"))
                    .and_then(|s| s.parse().ok()),
                self.read_string(&self.proc().join("sys/net/netfilter/nf_conntrack_max"))
                    .and_then(|s| s.parse().ok()),
            )
        } else {
            (None, None)
        };
        let present = self.scan_cmdline_contains();
        let firewalld = present.iter().any(|p| p.contains("firewalld"));
        let mut status = "ok".to_string();
        if selinux.is_none() {
            status = "warning".to_string();
        }
        NodeSecurity {
            selinux,
            firewalld_active: Some(firewalld),
            ipvs_loaded: Some(ipvs),
            br_netfilter_loaded: Some(br_netfilter),
            overlay_loaded: Some(overlay),
            nf_conntrack_loaded: Some(nf_conntrack),
            nf_conntrack_count: nf_count,
            nf_conntrack_max: nf_max,
            status,
            detail: String::new(),
        }
    }

    fn read_selinux(&self) -> Option<String> {
        let enforce = self.read_string(&self.sys().join("fs/selinux/enforce"));
        if let Some(e) = enforce {
            return match e.as_str() {
                "1" => Some("Enforcing".to_string()),
                "0" => Some("Permissive".to_string()),
                _ => None,
            };
        }
        if let Some(status) = self.read_string(&self.sys().join("fs/selinux/status")) {
            if status.contains("SELinux status:") && status.contains("disabled") {
                return Some("Disabled".to_string());
            }
        }
        if !self.sys().join("fs/selinux").exists() {
            return Some("Disabled".to_string());
        }
        if let Some(conf) = self.read_string(&self.etc().join("selinux/config")) {
            if conf
                .lines()
                .any(|l| l.trim_start().starts_with("SELINUX=disabled"))
            {
                return Some("Disabled".to_string());
            }
        }
        None
    }

    fn gather_stability(&self) -> NodeStability {
        let (inode_used_pct, _) = inode_usage(&self.mapped_path("/"));
        let oom = self.read_string(&self.proc().join("vmstat")).and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("oom_kill "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        });
        let file_nr = self.read_string(&self.proc().join("sys/fs/file-nr"));
        let (open, max) = match &file_nr {
            Some(s) => {
                let parts: Vec<&str> = s.split_whitespace().collect();
                (
                    parts.first().and_then(|v| v.parse().ok()),
                    parts.get(2).and_then(|v| v.parse().ok()),
                )
            }
            None => (None, None),
        };
        NodeStability {
            inode_used_pct,
            oom_kill_count: oom,
            file_nr_open: open,
            file_nr_max: max,
        }
    }

    fn gather_kernel(&self) -> NodeKernel {
        let forward = self.read_string(&self.proc().join("sys/net/ipv4/ip_forward"));
        let swappiness = self.read_string(&self.proc().join("sys/vm/swappiness"));
        let somaxconn = self.read_string(&self.proc().join("sys/net/core/somaxconn"));
        NodeKernel {
            net_ipv4_ip_forward: forward,
            vm_swappiness: swappiness,
            net_core_somaxconn: somaxconn,
            status: "ok".to_string(),
            detail: String::new(),
        }
    }

    fn count_zombie_processes(&self) -> u32 {
        let mut count = 0;
        let proc = self.proc();
        let Ok(entries) = std::fs::read_dir(&proc) else {
            return 0;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Ok(name) = name.into_string() else {
                continue;
            };
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) {
                let mut it = stat.split_whitespace();
                it.next(); // pid
                let _ = it.next(); // comm
                if let Some(state) = it.next() {
                    if state == "Z" {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// 扫描 /proc/{pid}/cmdline 的第一参数，返回进程名集合（作为字符串集合）。
    fn scan_cmdline_contains(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let proc = self.proc();
        let Ok(entries) = std::fs::read_dir(&proc) else {
            return out;
        };
        for entry in entries.flatten() {
            let is_pid = entry
                .file_name()
                .to_str()
                .map(|n| n.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
            if !is_pid {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path().join("cmdline")) {
                if let Some(first) = bytes.split(|&b| b == 0).next() {
                    let s = String::from_utf8_lossy(first);
                    if !s.is_empty() {
                        out.push(s.into_owned());
                    }
                }
            }
        }
        out
    }

    fn collect_certificates(&self) -> Vec<NodeCertificate> {
        // 简化版：扫描 kube/etcd 进程 cmdline 中的证书参数，读取文件用 x509-parser 计算剩余天数
        let mut paths = std::collections::BTreeMap::<String, ()>::new();
        const CERT_FLAGS: &[&str] = &[
            "client-ca-file",
            "tls-cert-file",
            "etcd-certfile",
            "etcd-cafile",
            "cert-file",
            "trusted-ca-file",
            "peer-cert-file",
            "peer-trusted-ca-file",
        ];
        let proc = self.proc();
        let Ok(entries) = std::fs::read_dir(&proc) else {
            return Vec::new();
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.into_string() else {
                continue;
            };
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let ppath = entry.path();
            let Ok(cmdline) = std::fs::read(ppath.join("cmdline")) else {
                continue;
            };
            let args: Vec<String> = cmdline
                .split(|&b| b == 0)
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .filter(|s| !s.is_empty())
                .collect();
            if args.is_empty() {
                continue;
            }
            let first = &args[0];
            if !(first.contains("kube-apiserver")
                || first.contains("kubelet")
                || first.contains("etcd")
                || first.contains("kube-controller")
                || first.contains("kube-scheduler"))
            {
                continue;
            }
            for (i, arg) in args.iter().enumerate() {
                if let Some(rest) = arg.strip_prefix("--") {
                    let (flag, inline) = match rest.split_once('=') {
                        Some((f, v)) => (f, Some(v.to_string())),
                        None => (rest, None),
                    };
                    if !CERT_FLAGS.contains(&flag) {
                        continue;
                    }
                    let path = inline.or_else(|| args.get(i + 1).map(|s| s.to_string()));
                    if let Some(p) = path {
                        paths.insert(p, ());
                    }
                }
            }
        }
        let mut certs = Vec::new();
        for p in paths.keys() {
            if p.ends_with(".key") {
                continue; // 跳过私钥
            }
            if let Some(expiration) = cert_expiry(&self.mapped_path_abs(p)) {
                let days = remaining_days(&expiration);
                let status = if days < 0 {
                    "Expired"
                } else if days < 30 {
                    "Expiring soon"
                } else {
                    "Valid"
                };
                certs.push(NodeCertificate {
                    path: p.clone(),
                    expiration_date: expiration.format("%Y-%m-%d").to_string(),
                    days_remaining: days,
                    status: status.to_string(),
                });
            }
        }
        certs
    }

    fn mapped_path_abs(&self, p: &str) -> PathBuf {
        if Path::new(p).exists() {
            PathBuf::from(p)
        } else {
            self.root.join(p.trim_start_matches('/'))
        }
    }
}

fn hostname_fallback(root: &str) -> String {
    let p = Path::new(root).join("proc/sys/kernel/hostname");
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        let days = secs / 86400;
        let rest = secs % 86400;
        let hours = rest / 3600;
        if hours > 0 {
            format!("{} day(s) {} hour(s)", days, hours)
        } else {
            format!("{} day(s)", days)
        }
    } else if secs >= 3600 {
        format!("{} hour(s) {} min", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{} sec", secs)
    }
}

fn meminfo_field(content: &Option<String>, key: &str) -> Option<u64> {
    let c = content.as_ref()?;
    c.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// 从 /proc/stat 的 cpu 行解析 (total, idle)
fn cpu_line_idle(content: &str) -> (Option<u64>, Option<u64>) {
    let Some(line) = content.lines().find(|l| l.starts_with("cpu ")) else {
        return (None, None);
    };
    let parts: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if parts.len() < 4 {
        return (None, None);
    }
    let total: u64 = parts.iter().sum();
    (Some(total), Some(parts[3]))
}

/// 磁盘使用统计：返回 (total_g, used_g, used_pct, root_used_pct)
fn disk_usage(path: &Path) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c = match CString::new(path.as_os_str().to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return (None, None, None, None),
        };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return (None, None, None, None);
        }
        let frag = st.f_frsize as f64;
        let total = st.f_blocks as f64 * frag;
        let free = st.f_bfree as f64 * frag;
        let used = total - free;
        let pct = if total > 0.0 {
            used / total * 100.0
        } else {
            0.0
        };
        let g = 1024.0 * 1024.0 * 1024.0;
        (Some(total / g), Some(used / g), Some(pct), Some(pct))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        (None, None, None, None)
    }
}

fn inode_usage(path: &Path) -> (Option<f64>, Option<f64>) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c = match CString::new(path.as_os_str().to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return (None, None),
        };
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
            return (None, None);
        }
        let files = st.f_files as f64;
        let free = st.f_ffree as f64;
        if files > 0.0 {
            let used_pct = (files - free) / files * 100.0;
            (Some(used_pct), Some(files - free))
        } else {
            (None, None)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        (None, None)
    }
}

fn compute_issue_count(
    r: &NodeResources,
    s: &NodeServices,
    sec: &NodeSecurity,
    k: &NodeKernel,
    zombie_count: u32,
) -> u32 {
    let mut count = 0;
    if r.status != "ok" {
        count += 1;
    }
    if s.status != "ok" {
        count += 1;
    }
    if sec.status != "ok" {
        count += 1;
    }
    if k.status != "ok" {
        count += 1;
    }
    if zombie_count > 0 {
        count += 1;
    }
    count
}

fn cert_expiry(path: &Path) -> Option<chrono::DateTime<Utc>> {
    let data = std::fs::read(path).ok()?;
    let (_rem, cert) = x509_parser::parse_x509_certificate(&data).ok()?;
    let secs: i64 = cert.validity().not_after.timestamp();
    chrono::DateTime::<Utc>::from_timestamp(secs, 0)
}

fn remaining_days(exp: &chrono::DateTime<Utc>) -> i64 {
    (exp.signed_duration_since(Utc::now()).num_seconds()) / 86400
}
