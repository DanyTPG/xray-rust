use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub static REDIR_TOTAL_ACCEPTED: AtomicU64 = AtomicU64::new(0);
pub static REDIR_TOTAL_CLOSED: AtomicU64 = AtomicU64::new(0);
pub static REDIR_ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
pub static DNS_TOTAL_QUERIES: AtomicU64 = AtomicU64::new(0);
pub static DNS_ACTIVE_QUERIES: AtomicU64 = AtomicU64::new(0);
pub static DNS_DOMESTIC_QUERIES: AtomicU64 = AtomicU64::new(0);
pub static DNS_REMOTE_QUERIES: AtomicU64 = AtomicU64::new(0);
pub static DNS_FAILOVER_QUERIES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub struct RedirTelemetry {
    pub redir_total_accepted: u64,
    pub redir_total_closed: u64,
    pub redir_active_connections: u64,
    pub dns_total_queries: u64,
    pub dns_active_queries: u64,
    pub dns_domestic_queries: u64,
    pub dns_remote_queries: u64,
    pub dns_failover_queries: u64,
}

pub fn redir_telemetry() -> RedirTelemetry {
    RedirTelemetry {
        redir_total_accepted: REDIR_TOTAL_ACCEPTED.load(Ordering::Relaxed),
        redir_total_closed: REDIR_TOTAL_CLOSED.load(Ordering::Relaxed),
        redir_active_connections: REDIR_ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
        dns_total_queries: DNS_TOTAL_QUERIES.load(Ordering::Relaxed),
        dns_active_queries: DNS_ACTIVE_QUERIES.load(Ordering::Relaxed),
        dns_domestic_queries: DNS_DOMESTIC_QUERIES.load(Ordering::Relaxed),
        dns_remote_queries: DNS_REMOTE_QUERIES.load(Ordering::Relaxed),
        dns_failover_queries: DNS_FAILOVER_QUERIES.load(Ordering::Relaxed),
    }
}

pub fn parse_dns_query_domain(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut domain = String::new();
    while pos < buf.len() {
        let len = buf[pos] as usize;
        if len == 0 {
            break;
        }
        if len > 63 || pos + 1 + len > buf.len() {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }
        let label = std::str::from_utf8(&buf[pos + 1..pos + 1 + len]).ok()?;
        domain.push_str(label);
        pos += 1 + len;
    }
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_ascii_lowercase())
    }
}

pub fn is_domestic_domain(domain: &str, matchers: &[xray_config::DomainMatcherSet]) -> bool {
    let lower = domain.trim_end_matches('.');
    if lower.ends_with(".ir") || lower == "ir" {
        return true;
    }
    for set in matchers {
        if set.matches(lower) {
            return true;
        }
    }
    false
}

pub async fn start_dns_forwarder(
    listen_port: u16,
    socks_addr: SocketAddr,
    direct_matchers: Arc<Vec<xray_config::DomainMatcherSet>>,
    domestic_dns: SocketAddr,
    remote_dns: SocketAddr,
) -> std::io::Result<()> {
    let listen_addr: SocketAddr = ([127, 0, 0, 1], listen_port).into();
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    eprintln!(
        "bound clean DNS forwarder at {listen_addr} (Domestic: {domestic_dns}, Remote: {remote_dns} -> socks at {socks_addr})"
    );

    let mut buf = [0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("dns forwarder recv error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };

        let query = buf[..len].to_vec();
        let sock_clone = Arc::clone(&socket);
        let matchers = Arc::clone(&direct_matchers);
        DNS_TOTAL_QUERIES.fetch_add(1, Ordering::Relaxed);
        DNS_ACTIVE_QUERIES.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            struct DnsGuard;
            impl Drop for DnsGuard {
                fn drop(&mut self) {
                    DNS_ACTIVE_QUERIES.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let _guard = DnsGuard;

            let domain = parse_dns_query_domain(&query);
            let is_domestic = domain
                .as_deref()
                .is_some_and(|d| is_domestic_domain(d, &matchers));

            let resp = if is_domestic {
                DNS_DOMESTIC_QUERIES.fetch_add(1, Ordering::Relaxed);
                resolve_dns_direct(&query, domestic_dns).await
            } else {
                DNS_REMOTE_QUERIES.fetch_add(1, Ordering::Relaxed);
                match resolve_dns_over_socks(&query, socks_addr, remote_dns).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        DNS_FAILOVER_QUERIES.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "remote dns query failed for {:?}: {e}; falling back to domestic dns",
                            domain.as_deref().unwrap_or("<unknown>")
                        );
                        resolve_dns_direct(&query, domestic_dns).await
                    }
                }
            };

            if let Ok(resp) = resp {
                let _ = sock_clone.send_to(&resp, peer).await;
            }
        });
    }
}

async fn resolve_dns_direct(query: &[u8], domestic_dns: SocketAddr) -> std::io::Result<Vec<u8>> {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, domestic_dns).await?;
        let mut buf = vec![0u8; 4096];
        let (len, _) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok(buf)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Domestic DNS query timed out"))?
}

async fn resolve_dns_over_socks(
    query: &[u8],
    socks_addr: SocketAddr,
    remote_dns: SocketAddr,
) -> std::io::Result<Vec<u8>> {
    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        let mut stream = TcpStream::connect(socks_addr).await?;

        // SOCKS5 Greeting: NO AUTH
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp != [0x05, 0x00] {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "SOCKS5 auth failed"));
        }

        // SOCKS5 CONNECT to remote_dns
        let mut req = Vec::with_capacity(22);
        req.extend_from_slice(&[0x05, 0x01, 0x00]);
        match remote_dns.ip() {
            std::net::IpAddr::V4(ip) => {
                req.push(0x01);
                req.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                req.push(0x04);
                req.extend_from_slice(&ip.octets());
            }
        }
        req.extend_from_slice(&remote_dns.port().to_be_bytes());
        stream.write_all(&req).await?;

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await?;
        if reply[1] != 0x00 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "SOCKS5 connect refused"));
        }

        // Skip bound address
        match reply[3] {
            0x01 => {
                let mut b = [0u8; 6];
                stream.read_exact(&mut b).await?;
            }
            0x04 => {
                let mut b = [0u8; 18];
                stream.read_exact(&mut b).await?;
            }
            0x03 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await?;
                let mut b = vec![0u8; l[0] as usize + 2];
                stream.read_exact(&mut b).await?;
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "invalid address type")),
        }

        // Send DNS query prefixed with 2-byte length
        let qlen = query.len() as u16;
        stream.write_all(&qlen.to_be_bytes()).await?;
        stream.write_all(query).await?;

        // Read 2-byte response length
        let mut rlen_buf = [0u8; 2];
        stream.read_exact(&mut rlen_buf).await?;
        let rlen = u16::from_be_bytes(rlen_buf) as usize;

        // Read DNS response
        let mut dns_resp = vec![0u8; rlen];
        stream.read_exact(&mut dns_resp).await?;

        Ok(dns_resp)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Remote DNS query timed out"))?
}

pub async fn start_redir_loop(listen_port: u16, socks_addr: SocketAddr) -> std::io::Result<()> {
    let idle_secs = std::env::var("XRAY_REDIR_IDLE_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let idle_timeout = Duration::from_secs(idle_secs);
    let listen_addr: SocketAddr = ([0, 0, 0, 0], listen_port).into();
    let listener = TcpListener::bind(listen_addr).await?;
    eprintln!("bound transparent proxy redirect inbound at {listen_addr} -> socks at {socks_addr} (idle timeout: {idle_secs}s)");

    loop {
        let (inbound, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("redir accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        REDIR_TOTAL_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        REDIR_ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            struct RedirGuard;
            impl Drop for RedirGuard {
                fn drop(&mut self) {
                    REDIR_TOTAL_CLOSED.fetch_add(1, Ordering::Relaxed);
                    REDIR_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let _guard = RedirGuard;
            if let Err(_e) = handle_redir_client(inbound, socks_addr, idle_timeout).await {
                // Client connection ended or errored
            }
        });
    }
}

async fn handle_redir_client(
    mut client: TcpStream,
    socks_addr: SocketAddr,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    let target = get_original_dst(&client)?;
    let mut socks = TcpStream::connect(socks_addr).await?;

    // SOCKS5 Greeting: NO AUTH
    socks.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    socks.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "SOCKS5 auth failed"));
    }

    // SOCKS5 CONNECT
    match target {
        SocketAddr::V4(v4) => {
            let mut req = [0u8; 10];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = 0x01; // IPv4
            req[4..8].copy_from_slice(&v4.ip().octets());
            req[8..10].copy_from_slice(&v4.port().to_be_bytes());
            socks.write_all(&req).await?;
        }
        SocketAddr::V6(v6) => {
            let mut req = [0u8; 22];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = 0x04; // IPv6
            req[4..20].copy_from_slice(&v6.ip().octets());
            req[20..22].copy_from_slice(&v6.port().to_be_bytes());
            socks.write_all(&req).await?;
        }
    }

    let mut reply = [0u8; 4];
    socks.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "SOCKS5 connect refused"));
    }

    // Skip bound address
    match reply[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            socks.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            socks.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            socks.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            socks.read_exact(&mut buf).await?;
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid SOCKS5 address type")),
    }

    copy_bidirectional_with_idle(&mut client, &mut socks, idle_timeout).await
}

async fn copy_bidirectional_with_idle(
    client: &mut TcpStream,
    socks: &mut TcpStream,
    idle_timeout: Duration,
) -> std::io::Result<()> {
    let (mut c_read, mut c_write) = client.split();
    let (mut s_read, mut s_write) = socks.split();

    let mut buf_c = [0u8; 8192];
    let mut buf_s = [0u8; 8192];

    let mut c_done = false;
    let mut s_done = false;

    while !c_done || !s_done {
        tokio::select! {
            res = tokio::time::timeout(idle_timeout, c_read.read(&mut buf_c)), if !c_done => {
                match res {
                    Ok(Ok(0)) => {
                        c_done = true;
                        let _ = s_write.shutdown().await;
                    }
                    Ok(Ok(n)) => {
                        s_write.write_all(&buf_c[..n]).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // Idle timeout
                }
            }
            res = tokio::time::timeout(idle_timeout, s_read.read(&mut buf_s)), if !s_done => {
                match res {
                    Ok(Ok(0)) => {
                        s_done = true;
                        let _ = c_write.shutdown().await;
                    }
                    Ok(Ok(n)) => {
                        c_write.write_all(&buf_s[..n]).await?;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_) => break, // Idle timeout
                }
            }
        }
    }
    let _ = s_write.shutdown().await;
    let _ = c_write.shutdown().await;
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
    }
}

#[cfg(not(target_os = "linux"))]
fn get_original_dst(_stream: &TcpStream) -> std::io::Result<SocketAddr> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST only supported on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query_domain() {
        // Query for "digikala.com"
        let query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // 8digikala3com0
            8, b'd', b'i', b'g', b'i', b'k', b'a', b'l', b'a',
            3, b'c', b'o', b'm',
            0,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];
        assert_eq!(parse_dns_query_domain(&query).as_deref(), Some("digikala.com"));

        // Query for "varzesh3.ir" with mixed case
        let query_ir = vec![
            0xaa, 0xbb,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            8, b'V', b'A', b'r', b'z', b'e', b's', b'h', b'3',
            2, b'I', b'R',
            0,
            0x00, 0x1c, // AAAA
            0x00, 0x01,
        ];
        assert_eq!(parse_dns_query_domain(&query_ir).as_deref(), Some("varzesh3.ir"));

        // Malformed / short queries
        assert_eq!(parse_dns_query_domain(&[]), None);
        assert_eq!(parse_dns_query_domain(&[0; 10]), None);
        assert_eq!(parse_dns_query_domain(&[0; 12]), None);
    }

    #[test]
    fn test_is_domestic_domain() {
        assert!(is_domestic_domain("varzesh3.ir", &[]));
        assert!(is_domestic_domain("sub.bank.ir", &[]));
        assert!(is_domestic_domain("ir", &[]));
        assert!(!is_domestic_domain("google.com", &[]));
        assert!(!is_domestic_domain("youtube.com", &[]));
    }
}
