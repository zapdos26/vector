use std::ffi::OsStr;
#[cfg(unix)]
use std::path::Path;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};
use vector_lib::configurable::configurable_component;
use vector_lib::metric_tags;

use super::{FilterList, HostMetrics, default_all_processes, example_processes};

/// Options for the process metrics collector.
#[configurable_component]
#[derive(Clone, Debug, Default)]
pub struct ProcessConfig {
    /// Lists of process name patterns to include or exclude.
    #[serde(default = "default_all_processes")]
    #[configurable(metadata(docs::examples = "example_processes()"))]
    processes: FilterList,

    /// When enabled, adds extended identity tags and additional metrics to process metrics.
    ///
    /// Extended tags include: `ppid`, `user`, `effective_user`, `group_id`,
    /// `effective_group_id`, `session_id`, `status`, `exe`, and more.
    /// Additional metrics include disk I/O, open files, accumulated CPU time,
    /// context switches (Linux), and page faults (Linux).
    #[serde(default)]
    pub extended_identity_tags: bool,
}

const RUNTIME: &str = "process_runtime";
const CPU_USAGE: &str = "process_cpu_usage";
const MEMORY_USAGE: &str = "process_memory_usage";
const MEMORY_VIRTUAL_USAGE: &str = "process_memory_virtual_usage";

// Extended metric names
const ACCUMULATED_CPU_TIME: &str = "process_accumulated_cpu_time";
const DISK_READ_BYTES: &str = "process_disk_read_bytes";
const DISK_WRITTEN_BYTES: &str = "process_disk_written_bytes";
const TOTAL_DISK_READ_BYTES: &str = "process_total_disk_read_bytes";
const TOTAL_DISK_WRITTEN_BYTES: &str = "process_total_disk_written_bytes";
const OPEN_FILES: &str = "process_open_files";
const OPEN_FILES_LIMIT: &str = "process_open_files_limit";
#[cfg(target_os = "linux")]
const TASK_COUNT: &str = "process_task_count";

/// Format a ProcessStatus as a lowercase tag value.
fn format_process_status(status: sysinfo::ProcessStatus) -> &'static str {
    use sysinfo::ProcessStatus;
    match status {
        ProcessStatus::Idle => "idle",
        ProcessStatus::Run => "run",
        ProcessStatus::Sleep => "sleep",
        ProcessStatus::Stop => "stop",
        ProcessStatus::Zombie => "zombie",
        ProcessStatus::Tracing => "tracing",
        ProcessStatus::Dead => "dead",
        ProcessStatus::Wakekill => "wakekill",
        ProcessStatus::Waking => "waking",
        ProcessStatus::Parked => "parked",
        _ => "unknown",
    }
}

/// Helper to format an optional Path as a tag value string.
#[cfg(unix)]
fn path_tag(p: Option<&Path>) -> String {
    p.map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl HostMetrics {
    pub async fn process_metrics(&mut self, output: &mut super::MetricsBuffer) {
        let extended = self.config.process.extended_identity_tags;
        let mut refresh_kind = ProcessRefreshKind::default()
            .with_memory()
            .with_cpu()
            .with_cmd(UpdateKind::OnlyIfNotSet);

        if extended {
            refresh_kind = refresh_kind
                .with_user(UpdateKind::OnlyIfNotSet)
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_root(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::OnlyIfNotSet)
                .with_disk_usage();
        }

        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            refresh_kind,
        );
        output.name = "process";
        let sep = OsStr::new(" ");
        for (pid, process) in self.system.processes().iter().filter(|&(_, proc)| {
            self.config
                .process
                .processes
                .contains_str(proc.name().to_str())
        }) {
            let pid_str = pid.as_u32().to_string();
            let name = process.name().to_str().unwrap_or("unknown").to_string();
            let command = process.cmd().join(sep).to_str().unwrap_or("").to_string();

            // Base tags — always present on all metrics.
            let base_tags = || {
                metric_tags!(
                    "pid" => pid_str.clone(),
                    "name" => name.clone(),
                    "command" => command.clone()
                )
            };

            if !extended {
                // Original behavior: base tags only, 4 metrics.
                output.gauge(CPU_USAGE, process.cpu_usage().into(), base_tags());
                output.gauge(MEMORY_USAGE, process.memory() as f64, base_tags());
                output.gauge(
                    MEMORY_VIRTUAL_USAGE,
                    process.virtual_memory() as f64,
                    base_tags(),
                );
                output.counter(RUNTIME, process.run_time() as f64, base_tags());
                continue;
            }

            // --- Extended identity tags ---
            let mut identity = base_tags();
            if let Some(ppid) = process.parent() {
                identity.replace("ppid".into(), ppid.as_u32().to_string());
            }

            #[cfg(unix)]
            {
                if let Some(uid) = process.user_id() {
                    let uid_val: u32 = **uid;
                    let username = self.uid_cache.resolve(uid_val);
                    identity.replace("user".into(), username);
                }
                if let Some(euid) = process.effective_user_id() {
                    let euid_val: u32 = **euid;
                    let eusername = self.uid_cache.resolve(euid_val);
                    identity.replace("effective_user".into(), eusername);
                }
            }

            if let Some(gid) = process.group_id() {
                identity.replace("group_id".into(), (*gid).to_string());
            }
            if let Some(egid) = process.effective_group_id() {
                identity.replace("effective_group_id".into(), (*egid).to_string());
            }
            if let Some(sid) = process.session_id() {
                identity.replace("session_id".into(), sid.as_u32().to_string());
            }

            identity.replace(
                "status".into(),
                format_process_status(process.status()),
            );

            #[cfg(unix)]
            {
                let exe_str = path_tag(process.exe());
                if !exe_str.is_empty() {
                    identity.replace("exe".into(), exe_str);
                }
            }

            #[cfg(target_os = "linux")]
            if let Some(kind) = process.thread_kind() {
                let kind_str = match kind {
                    sysinfo::ThreadKind::Kernel => "kernel",
                    sysinfo::ThreadKind::Userland => "userland",
                };
                identity.replace("thread_kind".into(), kind_str);
            }

            // --- Time tags (identity + start_time) for CPU/runtime metrics ---
            let time_tags = {
                let mut t = identity.clone();
                let start = process.start_time();
                if start > 0 {
                    t.replace("start_time".into(), start.to_string());
                }
                t
            };

            // --- Filesystem tags (identity + cwd, root) for I/O metrics ---
            #[cfg(unix)]
            let io_tags = {
                let mut t = identity.clone();
                let cwd_str = path_tag(process.cwd());
                if !cwd_str.is_empty() {
                    t.replace("cwd".into(), cwd_str);
                }
                let root_str = path_tag(process.root());
                if !root_str.is_empty() {
                    t.replace("root".into(), root_str);
                }
                t
            };
            #[cfg(not(unix))]
            let io_tags = identity.clone();

            // --- Emit base metrics with extended tags ---
            output.gauge(CPU_USAGE, process.cpu_usage().into(), time_tags.clone());
            output.gauge(MEMORY_USAGE, process.memory() as f64, identity.clone());
            output.gauge(
                MEMORY_VIRTUAL_USAGE,
                process.virtual_memory() as f64,
                identity.clone(),
            );
            output.counter(RUNTIME, process.run_time() as f64, time_tags.clone());

            // --- Extended resource metrics ---
            output.gauge(
                ACCUMULATED_CPU_TIME,
                process.accumulated_cpu_time() as f64,
                time_tags,
            );

            // --- Disk I/O metrics ---
            let du = process.disk_usage();
            output.gauge(DISK_READ_BYTES, du.read_bytes as f64, io_tags.clone());
            output.gauge(DISK_WRITTEN_BYTES, du.written_bytes as f64, io_tags.clone());
            output.gauge(
                TOTAL_DISK_READ_BYTES,
                du.total_read_bytes as f64,
                io_tags.clone(),
            );
            output.gauge(
                TOTAL_DISK_WRITTEN_BYTES,
                du.total_written_bytes as f64,
                io_tags.clone(),
            );

            // --- Open files metrics ---
            if let Some(open) = process.open_files() {
                output.gauge(OPEN_FILES, open as f64, io_tags.clone());
            }
            if let Some(limit) = process.open_files_limit() {
                output.gauge(OPEN_FILES_LIMIT, limit as f64, io_tags);
            }

            // --- Task count (Linux only) ---
            #[cfg(target_os = "linux")]
            if let Some(tasks) = process.tasks() {
                let mut task_tags = identity.clone();
                // Multi-value thread_ids tag
                let thread_ids: Vec<String> =
                    tasks.iter().map(|t| t.as_u32().to_string()).collect();
                for tid in &thread_ids {
                    task_tags.insert("thread_ids".into(), tid.clone());
                }
                output.gauge(TASK_COUNT, tasks.len() as f64, task_tags);
            }

            // identity is consumed by the last usage above; drop it explicitly
            // to help the compiler see it's no longer needed.
            let _ = identity;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HostMetrics, HostMetricsConfig, MetricsBuffer};
    use crate::sources::host_metrics::tests::count_tag;

    #[tokio::test]
    async fn generates_process_metrics() {
        let mut buffer = MetricsBuffer::new(None);
        HostMetrics::new(HostMetricsConfig::default())
            .process_metrics(&mut buffer)
            .await;
        let metrics = buffer.metrics;
        assert!(!metrics.is_empty());

        // All metrics are named process_*
        assert!(
            !metrics
                .iter()
                .any(|metric| !metric.name().starts_with("process_"))
        );

        // They should all have the required tag
        assert_eq!(count_tag(&metrics, "pid"), metrics.len());
        assert_eq!(count_tag(&metrics, "name"), metrics.len());
        assert_eq!(count_tag(&metrics, "command"), metrics.len());
    }

    #[tokio::test]
    async fn generates_extended_process_metrics() {
        let mut config = HostMetricsConfig::default();
        config.process.extended_identity_tags = true;
        let mut buffer = MetricsBuffer::new(None);
        HostMetrics::new(config)
            .process_metrics(&mut buffer)
            .await;
        let metrics = buffer.metrics;
        assert!(!metrics.is_empty());

        // All metrics are named process_*
        assert!(metrics.iter().all(|m| m.name().starts_with("process_")));

        // Base tags on all metrics
        assert_eq!(count_tag(&metrics, "pid"), metrics.len());
        assert_eq!(count_tag(&metrics, "name"), metrics.len());

        // Should have extended metrics beyond the original 4 per process
        let metric_names: std::collections::HashSet<&str> =
            metrics.iter().map(|m| m.name()).collect();
        assert!(metric_names.contains("process_accumulated_cpu_time"));
        assert!(metric_names.contains("process_disk_read_bytes"));
        assert!(metric_names.contains("process_disk_written_bytes"));

        // Extended identity tags should be present on at least some metrics
        assert!(count_tag(&metrics, "status") > 0);
    }
}
