use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use vector::sources::host_metrics::{HostMetrics, HostMetricsConfig};

fn bench_process_metrics(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("host_metrics_process");
    group.noise_threshold(0.05);
    group.sample_size(20);

    // Benchmark: collect all process metrics (default config — all processes, all metrics)
    group.bench_function("all_processes_all_metrics", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut host = HostMetrics::new(HostMetricsConfig::default());
                    let mut buffer = host.buffer();
                    host.process_metrics(&mut buffer).await;
                    std::hint::black_box(&buffer.metrics);
                }
                start.elapsed()
            })
        });
    });

    // Benchmark: collect only CPU and memory metrics via metric filter
    group.bench_function("all_processes_cpu_memory_only", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let config: HostMetricsConfig =
                    serde_json::from_value(serde_json::json!({
                        "process": {
                            "metrics": {
                                "includes": ["process_cpu_*", "process_memory_*"]
                            }
                        }
                    }))
                    .unwrap();
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut host = HostMetrics::new(config.clone());
                    let mut buffer = host.buffer();
                    host.process_metrics(&mut buffer).await;
                    std::hint::black_box(&buffer.metrics);
                }
                start.elapsed()
            })
        });
    });

    // Benchmark: single process filtered by name
    group.bench_function("single_process_all_metrics", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let config: HostMetricsConfig =
                    serde_json::from_value(serde_json::json!({
                        "process": {
                            "processes": {
                                "includes": ["vector"]
                            }
                        }
                    }))
                    .unwrap();
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut host = HostMetrics::new(config.clone());
                    let mut buffer = host.buffer();
                    host.process_metrics(&mut buffer).await;
                    std::hint::black_box(&buffer.metrics);
                }
                start.elapsed()
            })
        });
    });

    group.finish();
}

fn bench_process_metrics_scaling(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("host_metrics_process_scaling");
    group.noise_threshold(0.05);
    group.sample_size(10);

    // Measure how metric count scales — useful for comparing
    // "all metrics" vs "filtered" output volume
    for filter in &["*", "process_cpu_*", "process_memory_*", "process_disk_*"] {
        group.bench_with_input(
            BenchmarkId::new("metric_filter", filter),
            filter,
            |b, &filter| {
                b.iter_custom(|iters| {
                    rt.block_on(async {
                        let config: HostMetricsConfig =
                            serde_json::from_value(serde_json::json!({
                                "process": {
                                    "metrics": {
                                        "includes": [filter]
                                    }
                                }
                            }))
                            .unwrap();
                        let start = std::time::Instant::now();
                        for _ in 0..iters {
                            let mut host = HostMetrics::new(config.clone());
                            let mut buffer = host.buffer();
                            host.process_metrics(&mut buffer).await;
                            std::hint::black_box(&buffer.metrics);
                        }
                        start.elapsed()
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_uid_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("host_metrics_uid_cache");

    // Benchmark UID resolution with cache (warm)
    #[cfg(unix)]
    {
        use vector::sources::host_metrics::uid_cache::UidCache;

        group.bench_function("resolve_cached", |b| {
            let mut cache = UidCache::new();
            cache.resolve(0); // warm the cache
            b.iter(|| {
                std::hint::black_box(cache.resolve(0));
            });
        });

        group.bench_function("resolve_cold", |b| {
            b.iter_batched(
                UidCache::new,
                |mut cache| {
                    std::hint::black_box(cache.resolve(0));
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_process_metrics,
    bench_process_metrics_scaling,
    bench_uid_cache,
);
criterion_main!(benches);
