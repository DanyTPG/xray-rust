//! TCP fragment mask implementation matching official Xray-core Go.
//!
//! Provides TCP stream fragmentation and record splitting (for TLS ClientHello).

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use xray_config::{FragmentConfig, TcpMask};
use crate::{BoxedTransportStream, TransportStream};

pub fn rand_between(from: u64, to: u64) -> u64 {
    let (min, max) = if from <= to { (from, to) } else { (to, from) };
    if max.saturating_sub(min) <= 1 {
        min
    } else {
        rand::thread_rng().gen_range(min..max)
    }
}

pub struct FragmentStream<S> {
    inner: S,
    config: FragmentConfig,
    packet_count: u64,
    pending_queue: VecDeque<(Vec<u8>, u64)>,
    current_chunk: Option<Vec<u8>>,
    current_chunk_written: usize,
    delay_sleep: Option<Pin<Box<Sleep>>>,
}

impl<S> FragmentStream<S> {
    pub fn new(inner: S, config: FragmentConfig) -> Self {
        Self {
            inner,
            config,
            packet_count: 0,
            pending_queue: VecDeque::new(),
            current_chunk: None,
            current_chunk_written: 0,
            delay_sleep: None,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncWrite + Unpin> FragmentStream<S> {
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(sleep) = &mut self.delay_sleep {
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        self.delay_sleep = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            if let Some(chunk) = &self.current_chunk {
                while self.current_chunk_written < chunk.len() {
                    let to_write = &chunk[self.current_chunk_written..];
                    match Pin::new(&mut self.inner).poll_write(cx, to_write) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "failed to write fragment to inner stream",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            self.current_chunk_written += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                self.current_chunk = None;
                self.current_chunk_written = 0;
            }

            if let Some((chunk, delay_ms)) = self.pending_queue.pop_front() {
                self.current_chunk = Some(chunk);
                self.current_chunk_written = 0;
                if delay_ms > 0 {
                    let mut sleep = Box::pin(tokio::time::sleep(Duration::from_millis(delay_ms)));
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => {}
                        Poll::Pending => {
                            self.delay_sleep = Some(sleep);
                            return Poll::Pending;
                        }
                    }
                }
            } else {
                break;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        ready!(this.poll_flush_pending(cx))?;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        this.packet_count += 1;

        if this.config.is_tls_hello() {
            if this.packet_count != 1 || buf.len() <= 5 || buf[0] != 22 {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            let record_len = 5 + (((buf[3] as usize) << 8) | (buf[4] as usize));
            if buf.len() < record_len {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }

            let data = &buf[5..record_len];
            let merge_hello = this.config.merge_tls_hello_segments();
            let max_split = rand_between(this.config.max_split_min, this.config.max_split_max);
            let mut split_num = 0;
            let mut from = 0;
            let mut hello = Vec::new();

            loop {
                let (len_min, len_max) = this.config.length_for_segment(split_num);
                let rand_len = rand_between(len_min, len_max) as usize;
                let mut to = from + rand_len;
                if to > data.len() || (max_split > 0 && (split_num as u64) + 1 >= max_split) {
                    to = data.len();
                }
                let l = to - from;
                let mut chunk = Vec::with_capacity(5 + l);
                chunk.extend_from_slice(&buf[..3]);
                chunk.push((l >> 8) as u8);
                chunk.push(l as u8);
                chunk.extend_from_slice(&data[from..to]);
                from = to;

                if merge_hello {
                    hello.extend_from_slice(&chunk);
                } else {
                    let (delay_min, delay_max) = this.config.delay_for_segment(split_num);
                    let delay_ms = if delay_max > 0 {
                        rand_between(delay_min, delay_max)
                    } else {
                        0
                    };
                    this.pending_queue.push_back((chunk, delay_ms));
                }

                split_num += 1;
                if from == data.len() {
                    if !hello.is_empty() {
                        this.pending_queue.push_back((hello, 0));
                    }
                    if buf.len() > record_len {
                        this.pending_queue.push_back((buf[record_len..].to_vec(), 0));
                    }
                    break;
                }
            }

            let _ = this.poll_flush_pending(cx);
            return Poll::Ready(Ok(buf.len()));
        }

        if this.config.packets_from != 0
            && (this.packet_count < this.config.packets_from
                || this.packet_count > this.config.packets_to)
        {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        let max_split = rand_between(this.config.max_split_min, this.config.max_split_max);
        let mut split_num = 0;
        let mut from = 0;

        loop {
            let (len_min, len_max) = this.config.length_for_segment(split_num);
            let rand_len = rand_between(len_min, len_max) as usize;
            let mut to = from + rand_len;
            if to > buf.len() || (max_split > 0 && (split_num as u64) + 1 >= max_split) {
                to = buf.len();
            }
            let chunk = buf[from..to].to_vec();
            from = to;
            let (delay_min, delay_max) = this.config.delay_for_segment(split_num);
            let delay_ms = if delay_max > 0 {
                rand_between(delay_min, delay_max)
            } else {
                0
            };
            this.pending_queue.push_back((chunk, delay_ms));

            split_num += 1;
            if from >= buf.len() {
                break;
            }
        }

        let _ = this.poll_flush_pending(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: TransportStream> TransportStream for FragmentStream<S> {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

    fn poll_read_direct(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read_direct(cx, output)
    }

    fn poll_write_direct(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_direct(cx, input)
    }
}

/// Applies TCP mask layers in reverse order so the first mask configured
/// in JSON becomes the outermost layer, exactly matching official Xray-core Go.
pub fn apply_tcp_masks(
    mut stream: BoxedTransportStream,
    masks: &[TcpMask],
) -> BoxedTransportStream {
    for mask in masks.iter().rev() {
        match mask {
            TcpMask::Fragment(config) => {
                stream = Box::new(FragmentStream::new(stream, config.clone()));
            }
        }
    }
    stream
}
