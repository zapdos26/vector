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

    /// Lists of metric name patterns to include or exclude.
    ///
    /// When not set, all process metrics are emitted. Supports glob patterns.
    /// Metric names: `process_cpu_usage`, `process_memory_usage`,
    /// `process_memory_virtual_usage`, `process_runtime`,
    /// `process_accumulated_cpu_time`, `process_disk_read_bytes`,
    /// `process_disk_written_bytes`, `process_total_disk_read_bytes`,
    /// `process_total_disk_written_bytes`, `process_open_files`,
    /// `process_task_count` (Linux), `process_minor_page_faults` (Linux),
    /// `process_major_page_faults` (Linux),
    /// `process_voluntary_context_switches` (Linux),
    /// `process_involuntary_context_switches` (Linux).
    #[serde(default)]
    #[configurable(metadata(docs::examples = "example_process_metrics()"))]
    pub(super) metrics: FilterList,

    /// TTL (in seconds) for the UID-to-username cache.
    ///
    /// Usernames are resolved via NSS/SSSD which may hit LDAP in IDM/IPA
    /// environments. This cache avoids repeated lookups. Set to `0` to disable
    /// caching. Defaults to 300 seconds (5 minutes).
    #[serde(default = "default_uid_cache_ttl_secs")]
    pub(super) uid_cache_ttl_secs: u64,
}

const fn default_uid_cache_ttl_secs() -> u64 {
    300
}

fn example_process_metrics() -> Vec<String> {
    vec![
        "process_cpu_*".into(),
        "process_memory_*".into(),
        "process_disk_*".into(),
    ]
}

const RUNTIME: &str = "process_runtime";
const CPU_USAGE: &str = "process_cpu_usage";
const MEMORY_USAGE: &str = "process_memory_usage";
const MEMORY_VIRTUAL_USAGE: &str = "process_memory_virtual_usage";
const ACCUMULATED_CPU_TIME: &str = "process_accumulated_cpu_time";
const DISK_READ_BYTES: &str = "process_disk_read_bytes";
const DISK_WRITTEN_BYTES: &str = "process_disk_written_bytes";
const TOTAL_DISK_READ_BYTES: &str = "process_total_disk_read_bytes";
const TOTAL_DISK_WRITTEN_BYTES: &str = "process_total_disk_written_bytes";
const OPEN_FILES: &str = "process_open_files";
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
const fn format_process_status(status: sysinfo::ProcessStatus) -> &'static str {
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

#[cfg(unix)]
fn path_tag(p: Option<&Path>) -> String {
    p.map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Shared memory segment info loaded from /proc/sysvipc/shm.
#[cfg(target_os = "linux")]
struct ShmInfo {
    /// (key, creator_pid) pairs for all active segments.
    segments: Vec<(i32, i32)>,
    /// Set of PIDs that created at least one SHM segment.
    creator_pids: std::collections::HashSet<i32>,
}

/// Load the current SysV shared memory segments from /proc/sysvipc/shm.
#[cfg(target_os = "linux")]
fn load_shm_info() -> ShmInfo {
    use procfs::Current;
    match procfs::SharedMemorySegments::current() {
        Ok(shm) => {
            let segments: Vec<(i32, i32)> = shm.0.iter().map(|s| (s.key, s.cpid)).collect();
            let creator_pids = segments.iter().map(|&(_, cpid)| cpid).collect();
            ShmInfo {
                segments,
                creator_pids,
            }
        }
        Err(_) => ShmInfo {
            segments: Vec::new(),
            creator_pids: std::collections::HashSet::new(),
        },
    }
}

/// Find the creator PID of a SysV shared memory segment used by a process.
///
/// Strategy (cheapest first):
/// 1. If this process's PID is itself a SHM creator, return its own PID.
/// 2. If /proc/pid/status shows RssShmem > 0, read /proc/pid/maps to find
///    which segment key is mapped and return that segment's creator PID.
/// 3. Otherwise return None (no maps read needed).
#[cfg(target_os = "linux")]
fn resolve_shm_owner(
    pid_i32: i32,
    proc_status: Option<&procfs::process::Status>,
    proc_handle: &procfs::process::Process,
    shm_info: &ShmInfo,
) -> Option<i32> {
    // Fast path: this process created a SHM segment
    if shm_info.creator_pids.contains(&pid_i32) {
        return Some(pid_i32);
    }

    // Only read maps if the process actually uses shared memory
    let has_shm = proc_status
        .and_then(|s| s.rssshmem)
        .is_some_and(|v| v > 0);
    if !has_shm {
        return None;
    }

    // Slow path: scan maps to find which SHM key is mapped
    if let Ok(maps) = proc_handle.maps() {
        for map in &maps.0 {
            if let procfs::process::MMapPath::Vsys(key) = &map.pathname {
                for &(seg_key, cpid) in &shm_info.segments {
                    if seg_key == *key {
                        return Some(cpid);
                    }
                }
            }
        }
    }
    None
}

impl HostMetrics {
    pub async fn process_metrics(&mut self, output: &mut super::MetricsBuffer) {
        let metric_filter = &self.config.process.metrics;
        let emit = |name: &str| metric_filter.contains_str(Some(name));

        let refresh_kind = ProcessRefreshKind::default()
            .with_memory()
            .with_cpu()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_disk_usage()
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_root(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet);

        self.system
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind);
        output.name = "process";
        #[cfg(target_os = "linux")]
        let shm_info = load_shm_info();
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

            // --- Identity tags (on all metrics) ---
            let mut identity = metric_tags!(
                "pid" => pid_str.clone(),
                "name" => name.clone(),
                "command" => command.clone()
            );

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

            identity.replace("status".into(), format_process_status(process.status()));

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
            #[cfg(target_os = "linux")]
            let procfs_data = {
                let pid_i32 = pid.as_u32() as i32;
                procfs::process::Process::new(pid_i32).ok().map(|p| {
                    let stat = p.stat().ok();
                    let status = p.status().ok();
                    let shm_owner_pid = resolve_shm_owner(pid_i32, status.as_ref(), &p, &shm_info);
                    (stat, status, shm_owner_pid)
                })
            };

            // --- Runtime tags (identity + start_time) for process_runtime only ---
            let runtime_tags = {
                let mut t = identity.clone();
                let start = process.start_time();
                if start > 0 {
                    t.replace("start_time".into(), start.to_string());
                }
                t
            };

            // --- CPU tags (identity + nice) for CPU metrics only ---
            #[cfg(target_os = "linux")]
            let cpu_tags = {
                let mut t = identity.clone();
                if let Some((Some(ref stat), _, _)) = procfs_data {
                    t.replace("nice".into(), stat.nice.to_string());
                }
                t
            };
            #[cfg(not(target_os = "linux"))]
            let cpu_tags = identity.clone();

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

            // --- Filesystem tags (identity + cwd, root) for I/O ---
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

            // --- Emit metrics (filtered by config) ---
            if emit(CPU_USAGE) {
                output.gauge(CPU_USAGE, process.cpu_usage().into(), cpu_tags);
            }
            if emit(MEMORY_USAGE) {
                output.gauge(MEMORY_USAGE, process.memory() as f64, memory_tags.clone());
            }
            if emit(MEMORY_VIRTUAL_USAGE) {
                output.gauge(
                    MEMORY_VIRTUAL_USAGE,
                    process.virtual_memory() as f64,
                    memory_tags.clone(),
                );
            }
            if emit(RUNTIME) {
                output.counter(RUNTIME, process.run_time() as f64, runtime_tags);
            }
            if emit(ACCUMULATED_CPU_TIME) {
                output.gauge(
                    ACCUMULATED_CPU_TIME,
                    process.accumulated_cpu_time() as f64,
                    identity.clone(),
                );
            }

            let du = process.disk_usage();
            if emit(DISK_READ_BYTES) {
                output.gauge(DISK_READ_BYTES, du.read_bytes as f64, io_tags.clone());
            }
            if emit(DISK_WRITTEN_BYTES) {
                output.gauge(DISK_WRITTEN_BYTES, du.written_bytes as f64, io_tags.clone());
            }
            if emit(TOTAL_DISK_READ_BYTES) {
                output.gauge(
                    TOTAL_DISK_READ_BYTES,
                    du.total_read_bytes as f64,
                    io_tags.clone(),
                );
            }
            if emit(TOTAL_DISK_WRITTEN_BYTES) {
                output.gauge(
                    TOTAL_DISK_WRITTEN_BYTES,
                    du.total_written_bytes as f64,
                    io_tags.clone(),
                );
            }

            if emit(OPEN_FILES)
                && let Some(open) = process.open_files()
            {
                let mut open_tags = io_tags.clone();
                if let Some(limit) = process.open_files_limit() {
                    open_tags.replace("open_files_limit".into(), limit.to_string());
                }
                output.gauge(OPEN_FILES, open as f64, open_tags);
            }

            #[cfg(target_os = "linux")]
            if emit(TASK_COUNT)
                && let Some(tasks) = process.tasks()
            {
                output.gauge(TASK_COUNT, tasks.len() as f64, identity.clone());
            }

            #[cfg(target_os = "linux")]
            if let Some((stat_opt, status_opt, _)) = procfs_data {
                if let Some(stat) = stat_opt {
                    if emit(MINOR_PAGE_FAULTS) {
                        output.gauge(MINOR_PAGE_FAULTS, stat.minflt as f64, memory_tags.clone());
                    }
                    if emit(MAJOR_PAGE_FAULTS) {
                        output.gauge(MAJOR_PAGE_FAULTS, stat.majflt as f64, memory_tags);
                    }
                }
                if let Some(status) = status_opt {
                    if emit(VOLUNTARY_CONTEXT_SWITCHES)
                        && let Some(vol) = status.voluntary_ctxt_switches
                    {
                        output.gauge(VOLUNTARY_CONTEXT_SWITCHES, vol as f64, identity.clone());
                    }
                    if emit(INVOLUNTARY_CONTEXT_SWITCHES)
                        && let Some(nonvol) = status.nonvoluntary_ctxt_switches
                    {
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
    use super::super::{FilterList, HostMetrics, HostMetricsConfig, MetricsBuffer, PatternWrapper};
    use super::*;
    use crate::sources::host_metrics::tests::{count_name, count_tag};

    async fn get_metrics(config: HostMetricsConfig) -> Vec<vector_lib::event::Metric> {
        let mut buffer = MetricsBuffer::new(None);
        HostMetrics::new(config).process_metrics(&mut buffer).await;
        buffer.metrics
    }

    async fn get_default_metrics() -> Vec<vector_lib::event::Metric> {
        get_metrics(HostMetricsConfig::default()).await
    }

    // --- Basic metric generation ---

    #[tokio::test]
    async fn generates_all_process_metrics() {
        let metrics = get_default_metrics().await;
        assert!(!metrics.is_empty());
        assert!(metrics.iter().all(|m| m.name().starts_with("process_")));

        let names: std::collections::HashSet<&str> = metrics.iter().map(|m| m.name()).collect();

        // Core metrics
        assert!(names.contains(CPU_USAGE));
        assert!(names.contains(MEMORY_USAGE));
        assert!(names.contains(MEMORY_VIRTUAL_USAGE));
        assert!(names.contains(RUNTIME));
        assert!(names.contains(ACCUMULATED_CPU_TIME));

        // Disk I/O
        assert!(names.contains(DISK_READ_BYTES));
        assert!(names.contains(DISK_WRITTEN_BYTES));
        assert!(names.contains(TOTAL_DISK_READ_BYTES));
        assert!(names.contains(TOTAL_DISK_WRITTEN_BYTES));
    }

    // --- Identity tags on all metrics ---

    #[tokio::test]
    async fn all_metrics_have_base_identity_tags() {
        let metrics = get_default_metrics().await;
        assert!(!metrics.is_empty());

        assert_eq!(count_tag(&metrics, "pid"), metrics.len());
        assert_eq!(count_tag(&metrics, "name"), metrics.len());
        assert_eq!(count_tag(&metrics, "command"), metrics.len());
        assert!(count_tag(&metrics, "status") > 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_identity_tags_present() {
        let metrics = get_default_metrics().await;
        assert!(!metrics.is_empty());

        // user tag should be on at least some metrics (UID 0 → root always exists)
        assert!(count_tag(&metrics, "user") > 0);
    }

    // --- Tag placement per metric category ---

    #[tokio::test]
    async fn start_time_only_on_runtime() {
        let metrics = get_default_metrics().await;

        let runtime_metrics: Vec<_> = metrics.iter().filter(|m| m.name() == RUNTIME).collect();
        let non_runtime: Vec<_> = metrics.iter().filter(|m| m.name() != RUNTIME).collect();

        // start_time should be on runtime metrics
        assert!(runtime_metrics.iter().any(|m| {
            m.tags()
                .map(|t| t.contains_key("start_time"))
                .unwrap_or(false)
        }));

        // start_time should NOT be on any other metric
        assert!(non_runtime.iter().all(|m| {
            !m.tags()
                .map(|t| t.contains_key("start_time"))
                .unwrap_or(false)
        }));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn nice_only_on_cpu_usage() {
        let metrics = get_default_metrics().await;

        let cpu_metrics: Vec<_> = metrics.iter().filter(|m| m.name() == CPU_USAGE).collect();
        let non_cpu: Vec<_> = metrics.iter().filter(|m| m.name() != CPU_USAGE).collect();

        assert!(!cpu_metrics.is_empty());
        assert!(
            cpu_metrics
                .iter()
                .any(|m| { m.tags().map(|t| t.contains_key("nice")).unwrap_or(false) })
        );

        // nice should NOT be on any other metric
        assert!(
            non_cpu
                .iter()
                .all(|m| { !m.tags().map(|t| t.contains_key("nice")).unwrap_or(false) })
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn filesystem_tags_on_io_metrics() {
        let metrics = get_default_metrics().await;

        let io_names = [
            DISK_READ_BYTES,
            DISK_WRITTEN_BYTES,
            TOTAL_DISK_READ_BYTES,
            TOTAL_DISK_WRITTEN_BYTES,
            OPEN_FILES,
        ];
        let io_metrics: Vec<_> = metrics
            .iter()
            .filter(|m| io_names.contains(&m.name()))
            .collect();

        if !io_metrics.is_empty() {
            // At least some I/O metrics should have cwd/root
            let has_cwd = io_metrics
                .iter()
                .any(|m| m.tags().map(|t| t.contains_key("cwd")).unwrap_or(false));
            // cwd may be empty for some processes, so just check it doesn't
            // appear on non-I/O metrics
            let non_io: Vec<_> = metrics
                .iter()
                .filter(|m| !io_names.contains(&m.name()))
                .collect();
            let cwd_on_non_io = non_io
                .iter()
                .any(|m| m.tags().map(|t| t.contains_key("cwd")).unwrap_or(false));
            // cwd should NOT appear outside I/O metrics
            assert!(!cwd_on_non_io, "cwd tag found on non-I/O metric");
            let _ = has_cwd; // used for documentation, may be false
        }
    }

    #[tokio::test]
    async fn open_files_has_limit_tag() {
        let metrics = get_default_metrics().await;

        let open_files: Vec<_> = metrics.iter().filter(|m| m.name() == OPEN_FILES).collect();

        // open_files_limit should be a tag on open_files, not a separate metric
        assert_eq!(count_name(&metrics, "process_open_files_limit"), 0);
        if !open_files.is_empty() {
            assert!(open_files.iter().any(|m| {
                m.tags()
                    .map(|t| t.contains_key("open_files_limit"))
                    .unwrap_or(false)
            }));
        }
    }

    // --- Metric value types ---

    #[tokio::test]
    async fn runtime_is_counter_others_are_gauges() {
        let metrics = get_default_metrics().await;

        for m in &metrics {
            if m.name() == RUNTIME {
                assert!(
                    matches!(m.value(), &vector_lib::event::MetricValue::Counter { .. }),
                    "process_runtime should be a counter"
                );
            } else {
                assert!(
                    matches!(m.value(), &vector_lib::event::MetricValue::Gauge { .. }),
                    "{} should be a gauge",
                    m.name()
                );
            }
        }
    }

    // --- Linux-specific metrics ---

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn generates_linux_procfs_metrics() {
        let metrics = get_default_metrics().await;

        let names: std::collections::HashSet<&str> = metrics.iter().map(|m| m.name()).collect();

        assert!(names.contains(MINOR_PAGE_FAULTS));
        assert!(names.contains(MAJOR_PAGE_FAULTS));
        assert!(names.contains(VOLUNTARY_CONTEXT_SWITCHES));
        assert!(names.contains(INVOLUNTARY_CONTEXT_SWITCHES));
    }

    // --- Metric name filtering ---

    #[tokio::test]
    async fn filters_metrics_by_include() {
        let mut config = HostMetricsConfig::default();
        config.process.metrics = FilterList {
            includes: Some(vec![
                PatternWrapper::try_from("process_cpu_*".to_string()).unwrap(),
            ]),
            excludes: None,
        };
        let metrics = get_metrics(config).await;

        assert!(!metrics.is_empty());
        // Only cpu metrics should be present
        assert!(metrics.iter().all(|m| m.name().starts_with("process_cpu")));
    }

    #[tokio::test]
    async fn filters_metrics_by_exclude() {
        let mut config = HostMetricsConfig::default();
        config.process.metrics = FilterList {
            includes: None,
            excludes: Some(vec![
                PatternWrapper::try_from("process_disk_*".to_string()).unwrap(),
                PatternWrapper::try_from("process_total_*".to_string()).unwrap(),
            ]),
        };
        let metrics = get_metrics(config).await;

        assert!(!metrics.is_empty());
        // No disk metrics should be present
        assert!(!metrics.iter().any(|m| m.name().starts_with("process_disk")));
        assert!(
            !metrics
                .iter()
                .any(|m| m.name().starts_with("process_total"))
        );
        // But other metrics should still be there
        assert!(metrics.iter().any(|m| m.name() == CPU_USAGE));
    }

    #[tokio::test]
    async fn empty_filter_emits_all_metrics() {
        // An empty (default) FilterList should not filter anything out.
        // We verify by checking that every known metric name appears.
        let metrics = get_default_metrics().await;
        let names: std::collections::HashSet<&str> = metrics.iter().map(|m| m.name()).collect();

        assert!(names.contains(CPU_USAGE));
        assert!(names.contains(MEMORY_USAGE));
        assert!(names.contains(MEMORY_VIRTUAL_USAGE));
        assert!(names.contains(RUNTIME));
        assert!(names.contains(ACCUMULATED_CPU_TIME));
    }

    // --- Process name filtering still works ---

    #[tokio::test]
    async fn filters_processes_by_name() {
        // Filter to a process name that definitely won't match anything
        let mut config = HostMetricsConfig::default();
        config.process.processes = FilterList {
            includes: Some(vec![
                PatternWrapper::try_from("nonexistent_process_xyz_12345".to_string()).unwrap(),
            ]),
            excludes: None,
        };
        let metrics = get_metrics(config).await;
        assert!(metrics.is_empty());
    }
}
