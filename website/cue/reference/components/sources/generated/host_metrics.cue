package metadata

generated: components: sources: host_metrics: configuration: {
	cgroups: {
		description: """
			Options for the cgroups (controller groups) metrics collector.

			This collector is only available on Linux systems, and only supports either version 2 or hybrid cgroups.
			"""
		required: false
		type: object: options: {
			base: {
				description: "The base cgroup name to provide metrics for."
				required:    false
				type: string: examples: ["/", "system.slice/snapd.service"]
			}
			groups: {
				description: """
					Lists of cgroup name patterns to include or exclude in gathering
					usage metrics.
					"""
				required: false
				type: object: {
					examples: [{
						excludes: ["*.service"]
						includes: ["user.slice/*"]
					}]
					options: {
						excludes: {
							description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
						includes: {
							description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: {
								default: ["*"]
								items: type: string: {}
							}
						}
					}
				}
			}
			levels: {
				description: """
					The number of levels of the cgroups hierarchy for which to report metrics.

					A value of `1` means the root or named cgroup.
					"""
				required: false
				type: uint: {
					default: 100
					examples: [1, 3]
				}
			}
		}
	}
	collectors: {
		description: """
			The list of host metric collector services to use.

			Defaults to all collectors.
			"""
		required: false
		type: array: {
			default: ["cpu", "disk", "filesystem", "load", "host", "memory", "network", "process", "cgroups", "tcp"]
			items: type: string: {
				enum: {
					cgroups: """
						Metrics related to Linux control groups.

						Only available on Linux.
						"""
					cpu:        "Metrics related to CPU utilization."
					disk:       "Metrics related to disk I/O utilization."
					filesystem: "Metrics related to filesystem space utilization."
					host:       "Metrics related to the host."
					load:       "Metrics related to the system load average."
					memory:     "Metrics related to memory utilization."
					network:    "Metrics related to network utilization."
					process:    "Metrics related to Process utilization."
					tcp:        "Metrics related to TCP connections."
				}
				examples: ["cgroups", "cpu", "disk", "filesystem", "load", "host", "memory", "network", "tcp"]
			}
		}
	}
	disk: {
		description: "Options for the disk metrics collector."
		required:    false
		type: object: options: devices: {
			description: """
				Lists of device name patterns to include or exclude in gathering
				I/O utilization metrics.
				"""
			required: false
			type: object: {
				examples: [{
					excludes: ["dm-*"]
					includes: ["sda"]
				}]
				options: {
					excludes: {
						description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
						required: false
						type: array: items: type: string: {}
					}
					includes: {
						description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
						required: false
						type: array: {
							default: ["*"]
							items: type: string: {}
						}
					}
				}
			}
		}
	}
	filesystem: {
		description: "Options for the filesystem metrics collector."
		required:    false
		type: object: options: {
			devices: {
				description: """
					Lists of device name patterns to include or exclude in gathering
					usage metrics.
					"""
				required: false
				type: object: {
					examples: [{
						excludes: ["dm-*"]
						includes: ["sda"]
					}]
					options: {
						excludes: {
							description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
						includes: {
							description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: {
								default: ["*"]
								items: type: string: {}
							}
						}
					}
				}
			}
			filesystems: {
				description: """
					Lists of filesystem name patterns to include or exclude in gathering
					usage metrics.
					"""
				required: false
				type: object: {
					examples: [{
						excludes: ["ext*"]
						includes: ["ntfs"]
					}]
					options: {
						excludes: {
							description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
						includes: {
							description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: {
								default: ["*"]
								items: type: string: {}
							}
						}
					}
				}
			}
			mountpoints: {
				description: """
					Lists of mount point path patterns to include or exclude in gathering
					usage metrics.
					"""
				required: false
				type: object: {
					examples: [{
						excludes: ["/raid*"]
						includes: ["/home"]
					}]
					options: {
						excludes: {
							description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
						includes: {
							description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: {
								default: ["*"]
								items: type: string: {}
							}
						}
					}
				}
			}
		}
	}
	namespace: {
		description: "Overrides the default namespace for the metrics emitted by the source."
		required:    false
		type: string: default: "host"
	}
	network: {
		description: "Options for the network metrics collector."
		required:    false
		type: object: options: devices: {
			description: """
				Lists of device name patterns to include or exclude in gathering
				network utilization metrics.
				"""
			required: false
			type: object: {
				examples: [{
					excludes: ["dm-*"]
					includes: ["sda"]
				}]
				options: {
					excludes: {
						description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
						required: false
						type: array: items: type: string: {}
					}
					includes: {
						description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
						required: false
						type: array: {
							default: ["*"]
							items: type: string: {}
						}
					}
				}
			}
		}
	}
	process: {
		description: "Options for the process metrics collector."
		required:    false
		type: object: options: {
			metrics: {
				description: """
					Lists of metric name patterns to include or exclude.

					When not set, all process metrics are emitted. Supports glob patterns.
					Metric names: `process_cpu_usage`, `process_memory_usage`,
					`process_memory_virtual_usage`, `process_runtime`,
					`process_accumulated_cpu_time`, `process_disk_read_bytes`,
					`process_disk_written_bytes`, `process_total_disk_read_bytes`,
					`process_total_disk_written_bytes`, `process_open_files`,
					`process_task_count` (Linux), `process_minor_page_faults` (Linux),
					`process_major_page_faults` (Linux),
					`process_voluntary_context_switches` (Linux),
					`process_involuntary_context_switches` (Linux).
					"""
				required: false
				type: object: {
					examples: ["process_cpu_*", "process_memory_*", "process_disk_*"]
					options: {
						excludes: {
							description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
						includes: {
							description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
					}
				}
			}
			processes: {
				description: "Lists of process name patterns to include or exclude."
				required:    false
				type: object: {
					examples: [{
						excludes: null
						includes: ["docker"]
					}]
					options: {
						excludes: {
							description: """
																Any patterns which should be excluded.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: items: type: string: {}
						}
						includes: {
							description: """
																Any patterns which should be included.

																The patterns are matched using globbing.
																"""
							required: false
							type: array: {
								default: ["*"]
								items: type: string: {}
							}
						}
					}
				}
			}
			uid_cache_ttl_secs: {
				description: """
					TTL (in seconds) for the UID-to-username cache.

					Usernames are resolved via NSS/SSSD which may hit LDAP in IDM/IPA
					environments. This cache avoids repeated lookups. Set to `0` to disable
					caching. Defaults to 300 seconds (5 minutes).
					"""
				required: false
				type: uint: default: 0
			}
		}
	}
	scrape_interval_secs: {
		description: "The interval between metric gathering, in seconds."
		required:    false
		type: uint: {
			default: 15
			unit:    "seconds"
		}
	}
}
