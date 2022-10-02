mod clap;

use std::{
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Tag, XChaCha20Poly1305, XNonce,
};

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use futures::{future::Either, Future, Stream, StreamExt};
use headers::{HeaderName, HeaderValue};
use httparse::{Request, Status, EMPTY_HEADER};
use tokio_tun::{Tun, TunBuilder};
use zeroize::Zeroizing;

use self::clap::InstanceType;

#[derive(Clone, Copy)]
struct TCPProgressRX {
    len: Option<usize>,
    buf_len: [u8; 4],
    nbytes: usize,
    nbytes_len: usize,
}

#[derive(Clone, Copy)]
struct TCPProgressTX {
    buf: *const u8,
    len: usize,
    nbytes: usize,
    nbytes_len: usize,
}

#[tokio::main]
async fn main() {
    let config = clap::get_config();

    let mut tun = TunBuilder::new()
        .name(&config.interface_name)
        .tap(false)
        .packet_info(false) // Set to false to view raw packet
        .up();

    if let Some(address) = config.interface_address {
        tun = tun.address(address.addr()).netmask(address.netmask());
    }

    let mut tun = tun.try_build().expect("Failed to build TUN device");
    let mut i = 0;

    type StreamItem = (
        usize,
        Pin<Box<dyn Future<Output = Result<(TcpStream, SocketAddr)>> + Send>>,
    );

    let mut stream: Pin<Box<dyn Stream<Item = StreamItem>>> = match config.instance_type {
        InstanceType::Server(n) => {
            let listener = TcpListener::bind(n)
                .await
                .expect(&format!("Failed to bind to {}", n));

            Box::pin(futures::stream::poll_fn(move |cx| {
                let res = match listener.poll_accept(cx) {
                    Poll::Ready(n) => Poll::Ready(n),
                    Poll::Pending => {
                        i += 1;
                        println!("[{}] Waiting for a connection on {}", i, n);
                        return Poll::Pending;
                    }
                };

                res.map::<Option<StreamItem>, _>(|x| {
                    Some((
                        i,
                        Box::pin(async move {
                            let (mut stream, addr) = x?;
                            println!("[{}] Connection from {}", i, addr);

                            match http_proxy_server(&mut stream).await {
                                Ok(_) => {}
                                Err(e) => {
                                    stream.shutdown().await?;
                                    return Err(e);
                                }
                            }

                            Ok((stream, addr))
                        }),
                    ))
                })
            }))
        }
        InstanceType::Client(addr) => {
            let headers = config.headers.clone();

            Box::pin(futures::stream::poll_fn(move |_| {
                i += 1;

                let headers = headers.clone();

                println!("[{}] Connecting to {}", i, addr);

                let stream = match std::net::TcpStream::connect(addr) {
                    Ok(n) => n,
                    Err(e) => {
                        return Poll::Ready(Option::<StreamItem>::Some((
                            i,
                            Box::pin(async { Err(e) }),
                        )));
                    }
                };

                stream
                    .set_nonblocking(true)
                    .expect("Failed to set TCP socket to nonblocking mode");

                Poll::Ready(Option::<StreamItem>::Some((
                    i,
                    Box::pin(async move {
                        let mut stream = TcpStream::from_std(stream)?;
                        println!("[{}] Connected to {}", i, addr);

                        match http_proxy_client(&mut stream, &headers).await {
                            Ok(_) => {}
                            Err(e) => {
                                stream.shutdown().await?;
                                return Err(e);
                            }
                        }

                        Ok((stream, addr))
                    }),
                )))
            }))
        }
    };

    while let Some((i, n)) = stream.next().await {
        let (mut stream, _) = match n.await {
            Ok(n) => n,
            Err(e) => {
                println!("[{}] Error: {}", i, e);

                match config.instance_type {
                    InstanceType::Client(_) => {
                        println!("[{}] Waiting for 2 seconds", i);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        println!();
                    }
                    _ => {
                        println!("[{}] Closed connection\n", i);
                    }
                }

                continue;
            }
        };

        println!("[{}] Finished HTTP proxy exchange", i);

        if let Err(e) = handle_stream(&mut stream, &mut tun, &config.key, config.debug, i).await {
            println!("[{}] Error: {}", i, e);
        }

        stream.shutdown().await.ok();

        println!("[{}] Closed connection\n", i);
    }
}

async fn handle_stream(
    stream: &mut TcpStream,
    tun: &mut Tun,
    key: &Option<Zeroizing<clap::Key>>,
    debug: bool,
    index: usize,
) -> Result<()> {
    let cipher = key.as_ref().map(|key| XChaCha20Poly1305::new(&key.0));

    let mut buf_tun = [0u8; 65575 + 24 + 16];
    let mut buf_tcp = [0u8; 65575 + 24 + 16];

    let mut tcp_progress_rx: TCPProgressRX = TCPProgressRX {
        len: None,
        buf_len: [0u8; 4],
        nbytes: 0,
        nbytes_len: 0,
    };
    let mut tcp_progress_tx: Option<TCPProgressTX> = None;

    let (mut stream_rx, mut stream_tx) = stream.split();

    loop {
        let tun_read = async {
            if tcp_progress_tx.is_some() {
                return Either::Left(stream_tx.writable().await.map(|_| &mut tcp_progress_tx));
            }

            Either::Right(tun.read(&mut buf_tun[24 + 16..]).await)
        };

        let either = tokio::select! {
            v = tun_read => Either::Left(match v {
                Either::Left(v) => Either::Left(v?),
                Either::Right(v) => Either::Right(v?),
            }),
            v = next_packet(&mut stream_rx, &mut buf_tcp, &mut tcp_progress_rx, index, debug) => Either::Right(match v {
                Some(v) => v?,
                None => break,
            }),
        };

        match either {
            Either::Left(res) => match res {
                Either::Left(progress) => {
                    match send_packet(&mut stream_tx, progress.as_mut().unwrap(), index, debug)
                        .await
                    {
                        Ok(_) => {
                            progress.take();
                        }
                        Err(e) => {
                            progress.take();
                            return Err(e);
                        }
                    }
                }
                Either::Right(nbytes) => {
                    if debug {
                        println!("[{}] Read {} bytes from TUN device", index, nbytes);

                        debug_packet(
                            &buf_tun[24 + 16..24 + 16 + nbytes],
                            "Sending packet to stream",
                            index,
                        )?;
                    }

                    let mut offset = 24 + 16;

                    if let Some(cipher) = &cipher {
                        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                        let tag = cipher
                            .encrypt_in_place_detached(
                                &nonce,
                                b"",
                                &mut buf_tun[24 + 16..24 + 16 + nbytes],
                            )
                            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

                        buf_tun[..24].copy_from_slice(nonce.as_slice());
                        buf_tun[24..24 + 16].copy_from_slice(tag.as_slice());

                        offset = 0;
                    }

                    let buf = &buf_tun[offset..24 + 16 + nbytes];

                    tcp_progress_tx.replace(TCPProgressTX {
                        buf: buf.as_ptr(),
                        len: buf.len(),
                        nbytes: 0,
                        nbytes_len: 0,
                    });
                }
            },
            Either::Right(buf) => {
                let mut offset = 0;

                if debug {
                    println!("[{}] Read {} bytes from TCP stream", index, buf.len());
                }

                if let Some(cipher) = &cipher {
                    offset = 24 + 16;

                    let (header, buf) = buf.split_at_mut(24 + 16);

                    let nonce = XNonce::from_slice(&header[..24]);
                    let tag = Tag::from_slice(&header[24..]);

                    cipher
                        .decrypt_in_place_detached(nonce, b"", buf, tag)
                        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
                }

                let buf = &buf.as_ref()[offset..];

                if debug {
                    debug_packet(buf, "Received packet from stream", index)?;
                }

                tun.write_all(buf).await?;
            }
        }
    }

    Ok(())
}

async fn next_packet<'a, S>(
    stream: &mut S,
    buf: &'a mut [u8; 65575 + 24 + 16],
    progress: &mut TCPProgressRX,
    index: usize,
    debug: bool,
) -> Option<Result<&'a mut [u8]>>
where
    S: AsyncRead + Unpin,
{
    let len = match progress.len {
        Some(n) => n,
        None => {
            loop {
                progress.nbytes_len += match stream
                    .read(&mut progress.buf_len[progress.nbytes_len..])
                    .await
                {
                    Ok(n) => n,
                    Err(e) => return Some(Err(e)),
                };

                if progress.nbytes_len == progress.buf_len.len() {
                    break;
                }
            }

            progress.nbytes_len = 0;
            progress.len = Some(u32::from_be_bytes(progress.buf_len).try_into().unwrap());
            progress.len.unwrap()
        }
    };

    if progress.nbytes == 0 && debug {
        println!("[{}] Reading {} bytes from TCP stream", index, len);
    }

    loop {
        progress.nbytes += match stream.read(&mut buf[progress.nbytes..len]).await {
            Ok(n) if n != 0 => n,
            Ok(_) => return Some(Err(Error::new(ErrorKind::Other, "Unexpected EOF"))),
            Err(e) => return Some(Err(Error::new(ErrorKind::Other, format!("2 - {}", e)))),
        };

        if progress.nbytes == len {
            progress.len = None;
            progress.nbytes = 0;

            break Some(Ok(&mut buf[..len]));
        }
    }
}

async fn send_packet<'a, S>(
    stream: &mut S,
    progress: &mut TCPProgressTX,
    index: usize,
    debug: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let buf = unsafe { std::slice::from_raw_parts(progress.buf, progress.len) };

    if buf.len() > 65575 + 24 + 16 {
        return Err(Error::new(ErrorKind::Other, "Frame size too big"));
    }

    if progress.nbytes == 0 {
        if progress.nbytes_len == 0 && debug {
            println!("[{}] Writing {} bytes to TCP stream", index, buf.len());
        }

        let len: u32 = buf.len().try_into().unwrap();
        let len = len.to_be_bytes();

        loop {
            progress.nbytes_len += stream.write(&len[progress.nbytes_len..]).await?;

            if progress.nbytes_len == len.len() {
                break;
            }
        }
    }

    loop {
        let nbytes = stream.write(&buf[progress.nbytes..]).await?;

        if debug {
            println!(
                "[{}] Wrote {}/{} bytes to TCP stream",
                index,
                nbytes,
                buf.len()
            );
        }

        progress.nbytes += nbytes;

        if progress.nbytes == buf.len() {
            if debug {
                println!("[{}] Finished writing to TCP stream", index);
            }
            return Ok(());
        }
    }
}

async fn http_proxy_client(
    stream: &mut TcpStream,
    headers: &Option<Vec<(HeaderName, HeaderValue)>>,
) -> Result<()> {
    let mut headers_string = "GET / HTTP/1.1\r\n".to_string();

    if let Some(headers) = headers {
        for (name, value) in headers {
            headers_string.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap()));
        }
    }

    headers_string.push_str("\r\n");

    stream.write_all(headers_string.as_bytes()).await.unwrap();
    stream.read_exact(&mut [0u8; 19]).await.unwrap(); // HTTP/1.1 200 OK\r\n\r\n

    Ok(())
}

async fn http_proxy_server(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 1024];
    let mut nbytes = 0;

    loop {
        let mut headers = [EMPTY_HEADER; 16];
        let mut req = Request::new(&mut headers);

        nbytes += match timeout(Duration::from_secs(5), stream.read(&mut buf[nbytes..])).await {
            Ok(Ok(n)) if n != 0 => n,
            Ok(Ok(_)) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    match nbytes {
                        n if n == 1024 => "HTTP dummy request too large",
                        _ => "Stream reached EOF",
                    },
                ))
            }
            Ok(Err(e)) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to read dummy HTTP request: {}", e),
                ))
            }
            Err(_) => return Err(Error::new(ErrorKind::Other, "Connection timed out")),
        };

        match req.parse(&buf[..nbytes]) {
            Ok(Status::Complete(_)) => break,
            Ok(Status::Partial) => continue,
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
        }
    }

    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();

    Ok(())
}

fn debug_packet(buf: &[u8], msg: &str, index: usize) -> Result<()> {
    let packet = PacketHeaders::from_ip_slice(buf).map_err(|e| Error::new(ErrorKind::Other, e))?;

    println!(
        "[{}] {}: {} {} PAYLOAD_LEN={}",
        index,
        msg,
        match packet.ip.unwrap() {
            IpHeader::Version4(v4, _) => {
                let src = Ipv4Addr::from(v4.source);
                let dst = Ipv4Addr::from(v4.destination);

                format!("SRC={}; DST={}", src, dst)
            }
            IpHeader::Version6(v6, _) => {
                let src = Ipv6Addr::from(v6.source);
                let dst = Ipv6Addr::from(v6.destination);

                format!("SRC={}; DST={}", src, dst)
            }
        },
        match packet.transport.unwrap() {
            TransportHeader::Udp(n) => {
                format!(
                    "UDP={{SRC_PORT={}; DST_PORT={}}}",
                    n.source_port, n.destination_port
                )
            }
            TransportHeader::Tcp(n) => {
                format!(
                    "TCP={{SRC_PORT={}; DST_PORT={}}}",
                    n.source_port, n.destination_port
                )
            }
            TransportHeader::Icmpv4(n) => {
                format!("ICMPv4={{TYPE={}; CHECKSUM={}}}", "_", n.checksum)
            }
            TransportHeader::Icmpv6(n) => {
                format!("ICMPv6={{TYPE={}; CHECKSUM={}}}", "_", n.checksum)
            }
        },
        packet.payload.len()
    );

    Ok(())
}
