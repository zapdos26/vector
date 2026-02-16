Enhanced the `host_metrics` source process collector with rich identity tags and new metrics.

All process metrics now include tags: `ppid`, `user`, `effective_user`,
`group_id`, `effective_group_id`, `session_id`, `status`, `exe`, and `thread_kind` (Linux).
Category-specific tags are applied per metric: `nice` on CPU, `start_time` on runtime,
`shm_owner_pid` on memory, and `cwd`/`root` on I/O metrics.

New metrics added: `process_accumulated_cpu_time`, `process_disk_read_bytes`,
`process_disk_written_bytes`, `process_total_disk_read_bytes`,
`process_total_disk_written_bytes`, `process_open_files` (with `open_files_limit` tag),
`process_task_count` (Linux), `process_minor_page_faults` (Linux),
`process_major_page_faults` (Linux), `process_voluntary_context_switches` (Linux),
and `process_involuntary_context_switches` (Linux).

New configuration options: `process.metrics` FilterList for controlling which process
metrics are emitted (glob include/exclude), and `process.uid_cache_ttl_secs` for tuning
the UID-to-username cache TTL (default 300s) used in IDM/IPA/SSSD environments.

authors: zapdos26
