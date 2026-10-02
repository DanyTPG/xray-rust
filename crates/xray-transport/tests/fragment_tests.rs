use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_config::{FragmentConfig, TcpMask};
use xray_transport::fragment::{apply_tcp_masks, FragmentStream};
use xray_transport::TransportStream;

struct MockTransportStream {
    inner: tokio::io::DuplexStream,
}

impl AsyncRead for MockTransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MockTransportStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl TransportStream for MockTransportStream {
    fn release_record_alignment(&mut self) {}

    fn poll_read_direct(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }

    fn poll_write_direct(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, input)
    }
}

#[tokio::test]
async fn test_tlshello_fragmentation_merged() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mock = MockTransportStream { inner: client };

    let config = FragmentConfig {
        packets_from: 0,
        packets_to: 1,
        lengths_min: vec![0, 104, 1],
        lengths_max: vec![0, 104, 1],
        delays_min: vec![0],
        delays_max: vec![0],
        max_split_min: 0,
        max_split_max: 0,
    };

    let mut stream = FragmentStream::new(mock, config);

    // Build a mock TLS ClientHello record:
    // Header: [0x16, 0x03, 0x01, high_len, low_len]
    let payload = vec![0x42u8; 150];
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);

    stream.write_all(&record).await.unwrap();
    stream.flush().await.unwrap();

    let mut received = vec![0u8; 4096];
    use tokio::io::AsyncReadExt;
    let n = server.read(&mut received).await.unwrap();
    let received_data = &received[..n];

    // Verify it consists of multiple valid TLS records!
    let mut offset = 0;
    let mut record_count = 0;
    let mut reassembled = Vec::new();
    while offset < received_data.len() {
        assert_eq!(received_data[offset], 0x16);
        let rec_len = u16::from_be_bytes([received_data[offset + 3], received_data[offset + 4]]) as usize;
        offset += 5;
        reassembled.extend_from_slice(&received_data[offset..offset + rec_len]);
        offset += rec_len;
        record_count += 1;
    }

    assert!(record_count > 1, "Should have split into multiple records");
    assert_eq!(reassembled, payload, "Reassembled payload must match original payload");
}

#[tokio::test]
async fn test_apply_tcp_masks_layering() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mock: Box<dyn TransportStream> = Box::new(MockTransportStream { inner: client });

    let masks = vec![
        TcpMask::Fragment(FragmentConfig {
            packets_from: 0,
            packets_to: 1,
            lengths_min: vec![0, 104, 1],
            lengths_max: vec![0, 104, 1],
            delays_min: vec![0],
            delays_max: vec![0],
            max_split_min: 0,
            max_split_max: 0,
        }),
        TcpMask::Fragment(FragmentConfig {
            packets_from: 1,
            packets_to: 1,
            lengths_min: vec![114, 1],
            lengths_max: vec![114, 1],
            delays_min: vec![1],
            delays_max: vec![1],
            max_split_min: 11,
            max_split_max: 11,
        }),
    ];

    let mut stream = apply_tcp_masks(mock, &masks);

    let payload = vec![0x42u8; 150];
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);

    tokio::spawn(async move {
        stream.write_all(&record).await.unwrap();
        stream.flush().await.unwrap();
    });

    use tokio::io::AsyncReadExt;
    let mut total_received = Vec::new();
    let mut chunk = vec![0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_millis(100), server.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => total_received.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => panic!("read error: {:?}", e),
        }
    }

    assert!(!total_received.is_empty(), "Should receive fragmented data");
}
