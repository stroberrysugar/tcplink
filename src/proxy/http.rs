use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use headers::{HeaderName, HeaderValue};
use httparse::{Response, Status, EMPTY_HEADER};

#[derive(Hash, Clone)]
pub enum Address {
    Ip(IpAddr),
    Domain(Box<str>),
}

#[derive(Clone)]
pub struct Destination {
    pub host: Address,
    pub port: u16,
}

impl From<SocketAddr> for Destination {
    fn from(addr: SocketAddr) -> Self {
        Destination {
            host: Address::Ip(addr.ip()),
            port: addr.port(),
        }
    }
}

impl<'a> From<(&'a str, u16)> for Destination {
    fn from(addr: (&'a str, u16)) -> Self {
        let host = String::from(addr.0).into_boxed_str();
        Destination {
            host: Address::Domain(host),
            port: addr.1,
        }
    }
}

macro_rules! ensure_200 {
    ($code:expr) => {
        if $code != 200 {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("proxy return error: {}", $code),
            ));
        }
    };
}

const BUF_LEN: usize = 1024;

pub async fn http_proxy(
    stream: &mut TcpStream,
    addr: &Destination,
    user_pass_auth: &Option<(String, String)>,
    headers: Option<Vec<(HeaderName, HeaderValue)>>,
) -> io::Result<()> {
    let mut buf = build_request(addr, user_pass_auth, headers).into_bytes();
    stream.write_all(&buf).await?;

    // Parse HTTP response
    buf.clear();
    let mut bytes_read = 0;
    let mut sink = [0u8; BUF_LEN];
    loop {
        let mut headers = [EMPTY_HEADER; 16];
        let mut response = Response::new(&mut headers);
        buf.resize(bytes_read + BUF_LEN, 0);
        let peek_len = stream.peek(&mut buf).await?;
        bytes_read += peek_len;

        match response.parse(&buf[..bytes_read]) {
            Err(e) => return Err(io::Error::new(ErrorKind::Other, e)),
            Ok(Status::Partial) => {
                if let Some(code) = response.code {
                    ensure_200!(code);
                }
                if bytes_read > 64_000 {
                    return Err(io::Error::new(ErrorKind::Other, "response too large"));
                }
                // Drop peeked data from socket buffer
                stream.read(&mut sink[..peek_len]).await?;
            }
            Ok(Status::Complete(bytes_request)) => {
                ensure_200!(response.code.unwrap());
                let len = peek_len - (bytes_read - bytes_request);
                stream.read(&mut sink[..len]).await?;
                break;
            }
        }
    }

    Ok(())
}

fn build_request(
    addr: &Destination,
    user_pass_auth: &Option<(String, String)>,
    headers: Option<Vec<(HeaderName, HeaderValue)>>,
) -> String {
    let port = addr.port;
    let host = match addr.host {
        Address::Ip(ip) => match ip {
            IpAddr::V4(ip) => format!("{}:{}", ip, port),
            IpAddr::V6(ip) => format!("[{}]:{}", ip, port),
        },
        Address::Domain(ref s) => format!("{}:{}", s, port),
    };

    if let Some(user_pass_auth) = user_pass_auth {
        let auth = format!(
            "{username}:{password}",
            username = user_pass_auth.0,
            password = user_pass_auth.1
        );
        let basic_auth = base64::encode(&auth);

        let mut headers_string = format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Proxy-Authorization: Basic {basic_auth}\r\n",
            host = host,
            basic_auth = basic_auth,
        );

        for (name, value) in headers.unwrap_or(vec![]) {
            headers_string.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap()));
        }

        headers_string.push_str("\r\n");
        headers_string
    } else {
        format!(
            "CONNECT {host} HTTP/1.1\r\n\
             Host: {host}\r\n\r\n",
            host = host
        )
    }
}
