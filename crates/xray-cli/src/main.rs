#[global_allocator]
static GLOBAL: xray_cli::alloc_tracker::TrackingAllocator<mimalloc::MiMalloc> =
    xray_cli::alloc_tracker::TrackingAllocator::new(mimalloc::MiMalloc);

fn default_worker_threads() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    if cpus > 2 {
        cpus.saturating_sub(1)
    } else {
        cpus
    }
}

fn main() {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    let worker_threads = if let Some(val) = std::env::var_os("TOKIO_WORKER_THREADS") {
        val.to_str()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(default_worker_threads)
    } else {
        default_worker_threads()
    };
    builder.worker_threads(worker_threads);
    let runtime = builder.enable_all().build().expect("create Tokio runtime");
    runtime.block_on(run());
}

async fn run() {
    if let Err(error) = xray_cli::run_cli_with_shutdown(std::env::args(), async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("failed to wait for shutdown signal: {error}");
        }
    })
    .await
    {
        let code = match &error {
            xray_cli::CliError::ConfigCheckFailed { code } => i32::from(*code),
            xray_cli::CliError::InvalidArguments(_) | xray_cli::CliError::Output { .. } => 2,
            _ => 1,
        };
        // A check has already emitted its complete text or JSON report.
        if !matches!(error, xray_cli::CliError::ConfigCheckFailed { .. }) {
            eprintln!("{error}");
        }
        std::process::exit(code);
    }
}
