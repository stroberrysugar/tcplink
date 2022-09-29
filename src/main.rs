mod clap;
mod proxy;

use bytes::Bytes;
use etherparse::PacketHeaders;
use futures::{future::Either, SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tun::TunBuilder;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use self::clap::InstanceType;

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

    loop {
        let stream = match config.instance_type {
            InstanceType::Server(n) => {
                println!("Waiting for connections on {}", n);

                TcpListener::bind(n)
                    .await
                    .expect(&format!("Failed to bind to {}", n))
                    .accept()
                    .await
                    .map(|x| {
                        println!("Accepted connection from {}", x.1);
                        x.0
                    })
                    .expect("Failed to accept new connection")
            }
            InstanceType::Client(n) => match &config.http_proxy {
                Some(proxy) => {
                    let mut stream = TcpStream::connect(proxy.address)
                        .await
                        .expect(&format!("Failed to connect to proxy at {}", proxy.address));

                    crate::proxy::http_proxy(
                        &mut stream,
                        &n.into(),
                        &proxy.user_pass,
                        proxy.headers.clone(),
                    )
                    .await
                    .expect("Failed to connect to HTTP proxy");

                    stream
                }
                None => TcpStream::connect(n)
                    .await
                    .expect(&format!("Failed to connect to {}", n)),
            },
        };

        let mut stream = Framed::new(stream, LengthDelimitedCodec::new());

        loop {
            let mut buf = [0u8; 70000];

            let either = tokio::select! {
                v = tun.read(&mut buf) => Either::Left(v.unwrap()),
                v = stream.next() => Either::Right(match v {
                    Some(v) => v.unwrap(),
                    None => break,
                }),
            };

            match either {
                Either::Left(nbytes) => {
                    if config.debug {
                        let packet = PacketHeaders::from_ip_slice(&buf[..nbytes]).unwrap();

                        println!(
                            "Sending packet to stream: {:#?}\n{:#?}\n{:?}",
                            packet.ip.unwrap(),
                            packet.transport.unwrap(),
                            packet.payload
                        );
                    }

                    stream
                        .send(Bytes::copy_from_slice(&buf[..nbytes]))
                        .await
                        .unwrap();
                }
                Either::Right(bytes) => {
                    if config.debug {
                        let packet = PacketHeaders::from_ip_slice(bytes.as_ref()).unwrap();

                        println!(
                            "Received packet from stream: {:#?}\n{:#?}\n{:?}",
                            packet.ip.unwrap(),
                            packet.transport.unwrap(),
                            packet.payload
                        );
                    }

                    tun.write_all(bytes.as_ref()).await.unwrap();
                }
            }
        }

        println!("Lost connection");
    }
}
