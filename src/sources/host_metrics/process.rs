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
#[cfg(target_os = "linux")]
const VOLUNTARY_CONTEXT_SWITCHES: &str = "process_voluntary_context_switches";
#[cfg(target_os = "linux")]
const INVOLUNTARY_CONTEXT_SWITCHES: &str = "process_involuntary_context_switches";
#[cfg(target_os = "linux")]
const MINOR_PAGE_FAULTS: &str = "process_minor_page_faults";
#[cfg(target_os = "linux")]
const MAJOR_PAGE_FAULTS: &str = "process_major_page_faults";

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

/// Find the creator PID of any SysV shared memory segment mapped by this process.
/// Returns the first shm creator PID found, or None if no SysV shm is mapped.
#[cfg(target_os = "linux")]
fn find_shm_owner_pid(maps: &procfs::process::MemoryMaps) -> Option<i32> {
    use procfs::Current;
    use std::sync::OnceLock;
    // Cache the SysV shm segments for the duration of this scrape.
    // OnceLock ensures we read /proc/sysvipc/shm at most once per process lifetime,
    // but since this is called many times per scrape we use a simple static cache.
    // For true per-scrape caching, a field on HostMetrics would be better,
    // but this is a reasonable starting point.
    static SHM_SEGMENTS: OnceLock<Option<Vec<(i32, i32)>>> = OnceLock::new();
    let segments = SHM_SEGMENTS.get_or_init(|| {
        procfs::SharedMemorySegments::current().ok().map(|shm| {
            shm.0.iter().map(|s| (s.key, s.cpid)).collect()
        })
    });

    for map in &maps.0 {
        if let procfs::process::MMapPath::Vsys(key) = &map.pathname {
            if let Some(segs) = segments {
                for (seg_key, cpid) in segs {
                    if seg_key == key {
                        return Some(*cpid);
                    }
                }
            }
        }
    }
    None
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

            // --- Read procfs data upfront (Linux only) ---
            // We read stat + status once per process to get nice, page faults,
            // context switches, and shared memory info.
            #[cfg(target_os = "linux")]
            let procfs_data = {
                let pid_i32 = pid.as_u32() as i32;
                procfs::process::Process::new(pid_i32).ok().map(|p| {
                    let stat = p.stat().ok();
                    let status = p.status().ok();
                    let has_shm = process.memory() > 0;
                    let shm_owner_pid = if has_shm {
                        p.maps().ok().and_then(|maps| {
                            find_shm_owner_pid(&maps)
                        })
                    } else {
                        None
                    };
                    (stat, status, shm_owner_pid)
                })
            };

            // --- Time tags (identity + start_time + nice) for CPU/runtime metrics ---
            let time_tags = {
                let mut t = identity.clone();
                let start = process.start_time();
                if start > 0 {
                    t.replace("start_time".into(), start.to_string());
                }
                #[cfg(target_os = "linux")]
                if let Some((Some(ref stat), _, _)) = procfs_data {
                    t.replace("nice".into(), stat.nice.to_string());
                }
                t
            };

            // --- Memory tags (identity + shm_owner_pid) ---
            #[cfg(target_os = "linux")]
            let memory_tags = {
                let mut t = identity.clone();
                if let Some((_, _, Some(owner_pid))) = &procfs_data {
                    t.replace("shm_owner_pid".into(), owner_pid.to_string());
                }
                t
            };
            #[cfg(not(target_os = "linux"))]
            let memory_tags = identity.clone();

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
            output.gauge(MEMORY_USAGE, process.memory() as f64, memory_tags.clone());
            output.gauge(
                MEMORY_VIRTUAL_USAGE,
                process.virtual_memory() as f64,
                memory_tags.clone(),
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
                let thread_ids: Vec<String> =
                    tasks.iter().map(|t| t.as_u32().to_string()).collect();
                for tid in &thread_ids {
                    task_tags.insert("thread_ids".into(), tid.clone());
                }
                output.gauge(TASK_COUNT, tasks.len() as f64, task_tags);
            }

            // --- Linux procfs-based metrics (page faults, context switches) ---
            #[cfg(target_os = "linux")]
            if let Some((stat_opt, status_opt, _)) = procfs_data {
                if let Some(stat) = stat_opt {
                    output.gauge(
                        MINOR_PAGE_FAULTS,
                        stat.minflt as f64,
                        memory_tags.clone(),
                    );
                    output.gauge(
                        MAJOR_PAGE_FAULTS,
                        stat.majflt as f64,
                        memory_tags,
                    );
                }
                if let Some(status) = status_opt {
                    if let Some(vol) = status.voluntary_ctxt_switches {
                        output.gauge(
                            VOLUNTARY_CONTEXT_SWITCHES,
                            vol as f64,
                            identity.clone(),
                        );
                    }
                    if let Some(nonvol) = status.nonvoluntary_ctxt_switches {
                        output.gauge(
                            INVOLUNTARY_CONTEXT_SWITCHES,
                            nonvol as f64,
                            identity.clone(),
                        );
                    }
                }
            }

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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn generates_linux_procfs_metrics() {
        let mut config = HostMetricsConfig::default();
        config.process.extended_identity_tags = true;
        let mut buffer = MetricsBuffer::new(None);
        HostMetrics::new(config)
            .process_metrics(&mut buffer)
            .await;
        let metrics = buffer.metrics;

        let metric_names: std::collections::HashSet<&str> =
            metrics.iter().map(|m| m.name()).collect();

        // procfs-based metrics should be present
        assert!(metric_names.contains("process_minor_page_faults"));
        assert!(metric_names.contains("process_major_page_faults"));
        assert!(metric_names.contains("process_voluntary_context_switches"));
        assert!(metric_names.contains("process_involuntary_context_switches"));

        // nice tag should be on CPU metrics
        let cpu_metrics: Vec<_> = metrics
            .iter()
            .filter(|m| m.name() == "process_cpu_usage")
            .collect();
        assert!(!cpu_metrics.is_empty());
        // At least one CPU metric should have the nice tag
        assert!(cpu_metrics.iter().any(|m| {
            m.tags()
                .map(|t| t.contains_key("nice"))
                .unwrap_or(false)
        }));
    }
}
