use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use xray_core_rs::ConnectionRegistry;

pub fn start_telemetry(registry: Arc<ConnectionRegistry>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        let mut sigusr1 = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("failed to register SIGUSR1 signal handler: {e}");
                None
            }
        };

        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let report = generate_report(&registry);
                    let _ = std::fs::write("/tmp/xray-rust-status.txt", &report);
                }
                _ = async {
                    #[cfg(unix)]
                    if let Some(ref mut sig) = sigusr1 {
                        sig.recv().await;
                        return;
                    }
                    std::future::pending::<()>().await;
                } => {
                    let report = generate_report(&registry);
                    let _ = std::fs::write("/tmp/xray-rust-status.txt", &report);
                    eprintln!("{report}");
                }
            }
        }
    });
}

pub fn generate_report(registry: &ConnectionRegistry) -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let (vm_rss, rss_anon, vm_size) = read_proc_mem();
    let (minflt, majflt) = read_page_faults();
    let fd_count = count_open_fds();
    let heap = crate::alloc_tracker::alloc_telemetry();

    let redir = crate::redir::redir_telemetry();
    let xhttp = xray_core_rs::xhttp_telemetry();

    let conn_snapshot = registry.snapshot();
    let acct_snapshot = registry.accounting_snapshot();

    let mut out = String::with_capacity(2048);
    out.push_str("======================= XRAY-RUST LIVE TELEMETRY =======================\n");
    out.push_str(&format!(
        "Memory (OS):   VmRSS: {} | RssAnon: {} | VmSize: {} | FDs: {} | Faults: (min:{}, maj:{})\n",
        vm_rss, rss_anon, vm_size, fd_count, minflt, majflt
    ));
    let live_heap_str = format_i64_bytes(heap.active_bytes);
    let peak_heap_str = format_i64_bytes(heap.peak_bytes);
    let small_str = format_i64_bytes(heap.small_bytes);
    let med_str = format_i64_bytes(heap.medium_bytes);
    let large_str = format_i64_bytes(heap.large_bytes);
    let live_blocks = heap.alloc_count.saturating_sub(heap.dealloc_count);
    out.push_str(&format!(
        "Rust Heap:     Live: {} | Peak: {} | Active Blocks: {} ({} allocs, {} frees)\n",
        live_heap_str, peak_heap_str, live_blocks, heap.alloc_count, heap.dealloc_count
    ));
    out.push_str(&format!(
        "Heap Classes:  Small(<1K): {} | Medium(1-64K): {} | Large(>64K): {}\n",
        small_str, med_str, large_str
    ));
    out.push_str(&format!(
        "Transparent Redir: Active: {} | Total Accepted: {} | Total Closed: {}\n",
        redir.redir_active_connections, redir.redir_total_accepted, redir.redir_total_closed
    ));
    out.push_str(&format!(
        "Clean DNS (5335):  Active: {} | Total Queries: {}\n",
        redir.dns_active_queries, redir.dns_total_queries
    ));
    out.push_str(&format!(
        "XHTTP H2 Pool:     Active Conn: {} | Total Dialed: {} | Closed: {} | Active Streams: {}\n",
        xhttp.h2_active_connections, xhttp.h2_total_dialed, xhttp.h2_total_closed, xhttp.h2_active_streams
    ));
    out.push_str(&format!(
        "Core Flow Registry: Active Flows: {}\n",
        conn_snapshot.connections.len()
    ));

    out.push_str("Outbound Accounting:\n");
    for acct in &acct_snapshot.outbounds {
        let tag = acct.outbound_tag.as_deref().unwrap_or("<default>");
        let active = acct.opened_connections.saturating_sub(acct.completed_connections);
        out.push_str(&format!(
            "  - {:<10} active: {:<4} | opened: {:<6} | completed: {:<6} | up: {} | down: {}\n",
            tag,
            active,
            acct.opened_connections,
            acct.completed_connections,
            format_bytes(acct.uplink_bytes),
            format_bytes(acct.downlink_bytes)
        ));
    }

    if !conn_snapshot.connections.is_empty() {
        let mut sorted = conn_snapshot.connections;
        sorted.sort_by_key(|c| c.started_unix_ms);
        let show_count = sorted.len().min(10);
        out.push_str(&format!("Longest Active Flows (showing top {}):\n", show_count));
        for (i, c) in sorted.iter().take(show_count).enumerate() {
            let age_secs = now_ms.saturating_sub(c.started_unix_ms) / 1000;
            let in_tag = c.inbound_tag.as_deref().unwrap_or("-");
            let out_tag = c.outbound_tag.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "  #{:<2} [{}s] in:{} -> out:{} | {:?}\n",
                i + 1, age_secs, in_tag, out_tag, c.target
            ));
        }
    }
    out.push_str("========================================================================\n");
    out
}

fn read_proc_mem() -> (String, String, String) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return ("N/A".into(), "N/A".into(), "N/A".into());
    };
    let mut vmrss = "N/A".to_string();
    let mut rssanon = "N/A".to_string();
    let mut vmsize = "N/A".to_string();
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            vmrss = line.trim_start_matches("VmRSS:").trim().to_string();
        } else if line.starts_with("RssAnon:") {
            rssanon = line.trim_start_matches("RssAnon:").trim().to_string();
        } else if line.starts_with("VmSize:") {
            vmsize = line.trim_start_matches("VmSize:").trim().to_string();
        }
    }
    (vmrss, rssanon, vmsize)
}

fn count_open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_i64_bytes(bytes: i64) -> String {
    if bytes < 0 {
        format!("-{}", format_bytes((-bytes) as u64))
    } else {
        format_bytes(bytes as u64)
    }
}

fn read_page_faults() -> (u64, u64) {
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(after_paren) = stat.rfind(')') {
            let fields: Vec<&str> = stat[after_paren + 1..].split_whitespace().collect();
            if fields.len() > 9 {
                let minflt = fields[7].parse().unwrap_or(0);
                let majflt = fields[9].parse().unwrap_or(0);
                return (minflt, majflt);
            }
        }
    }
    (0, 0)
}
