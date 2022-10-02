mod clap;

use std::{
    io::{Error, ErrorKind, Result},
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::Poll,
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Tag, XChaCha20Poly1305, XNonce,
};

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use futures::{Future, Stream, StreamExt};
use headers::{HeaderName, HeaderValue};
use httparse::{Request, Status, EMPTY_HEADER};
use tokio_tun::{Tun, TunBuilder};
use zeroize::Zeroizing;

use self::clap::InstanceType;

const TUN_RX: Mutex<MaybeUninit<ReadHalf<Tun>>> = Mutex::new(MaybeUninit::uninit());
const TUN_TX: Mutex<MaybeUninit<WriteHalf<Tun>>> = Mutex::new(MaybeUninit::uninit());

#[derive(Clone, Copy)]
struct TCPProgress {
    len: usize,
    nbytes: usize,
}

#[tokio::main]
async fn main() {
    let config = clap::get_config();

    /*let mut tun = tun::Configuration::default();

    tun.name(&config.interface_name).up();

    if let Some(address) = config.interface_address {
        tun.address(address.addr()).netmask(address.netmask());
    }

    let mut tun = tun::create(&tun).expect("Failed to create TUN device");*/

    let mut tun = TunBuilder::new()
        .name(&config.interface_name)
        .tap(false)
        .packet_info(false) // Set to false to view raw packet
        .up();

    if let Some(address) = config.interface_address {
        tun = tun.address(address.addr()).netmask(address.netmask());
    }

    let tun = tun.try_build().expect("Failed to build TUN device");
    let (tun_rx, tun_tx) = tokio::io::split(tun);

    TUN_RX.lock().unwrap().write(tun_rx);
    TUN_TX.lock().unwrap().write(tun_tx);

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
        let (stream, _) = match n.await {
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

        let (stream1, stream2) = match stream
            .into_std()
            .and_then(|x| x.try_clone().map(|y| (x, y)))
            .and_then(|(x, y)| TcpStream::from_std(x).map(|x| (x, y)))
        {
            Ok(n) => n,
            Err(e) => {
                println!("[{}] Failed to clone TcpStream: {}", i, e);
                println!("[{}] Closed connection\n", i);
                continue;
            }
        };

        if let Err(e) = handle_stream(stream1, &config.key, config.debug, i).await {
            println!("[{}] Error: {}", i, e);
        }

        stream2.shutdown(Shutdown::Both).ok();

        println!("[{}] Closed connection\n", i);
    }
}

async fn handle_stream(
    stream: TcpStream,
    key: &Option<Zeroizing<clap::Key>>,
    debug: bool,
    index: usize,
) -> std::result::Result<(), Error> {
    let cipher = key.as_ref().map(|key| XChaCha20Poly1305::new(&key.0));

    let mut buf_tun = [0u8; 65575 + 24 + 16];
    let mut buf_tcp = [0u8; 65575 + 24 + 16];

    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(stream);

    let tun_handle = tokio::spawn(async move { loop {} });

    let tcp_handle = tokio::spawn(async move {
        let mut tcp_progress = None;

        loop {
            next_packet(&mut tcp_rx, &mut buf_tcp, &mut tcp_progress, index);
        }
    });

    todo!()
}

async fn next_packet<'a, S>(
    stream: &mut S,
    buf: &'a mut [u8; 65575 + 24 + 16],
    progress_opt: &mut Option<TCPProgress>,
    index: usize,
) -> Option<Result<&'a mut [u8]>>
where
    S: AsyncRead + Unpin,
{
    let progress = match progress_opt {
        Some(n) => n,
        None => {
            let mut len = [0u8; 4];

            match stream.read_exact(&mut len).await {
                Ok(n) if n == 4 => {}
                Ok(_) => return Some(Err(Error::new(ErrorKind::Other, "Unexpected EOF"))),
                Err(e) => {
                    return Some(Err(Error::new(
                        ErrorKind::Other,
                        format!("1 - {} - {:?}", e, len),
                    )))
                }
            }

            let len = u32::from_be_bytes(len).try_into().unwrap();

            println!("[{}] Reading {} bytes from TCP stream", index, len);

            if len > buf.len() {
                return Some(Err(Error::new(
                    ErrorKind::Other,
                    format!("Frame size too big: {}", len),
                )));
            }

            progress_opt.replace(TCPProgress { len, nbytes: 0 });
            progress_opt.as_mut().unwrap()
        }
    };

    loop {
        progress.nbytes += match stream
            .read_exact(&mut buf[progress.nbytes..progress.len])
            .await
        {
            Ok(n) if n != 0 => n,
            Ok(_) => return Some(Err(Error::new(ErrorKind::Other, "Unexpected EOF"))),
            Err(e) => return Some(Err(Error::new(ErrorKind::Other, format!("2 - {}", e)))),
        };

        if progress.nbytes == progress.len {
            let len = progress.len;
            progress_opt.take();
            break Some(Ok(&mut buf[..len]));
        }
    }
}

async fn send_packet<'a>(stream: &mut TcpStream, buf: &[u8], index: usize) -> Result<()> {
    if buf.len() > 65575 + 24 + 16 {
        return Err(Error::new(ErrorKind::Other, "Frame size too big"));
    }

    println!("[{}] Writing {} bytes to TCP stream", index, buf.len());

    let len: u32 = buf.len().try_into().unwrap();
    let len = len.to_be_bytes();

    stream.write_all(&len).await?;
    stream.write_all(buf).await?;

    Ok(())
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
