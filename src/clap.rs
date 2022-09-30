use std::{io::Read, net::SocketAddr, path::PathBuf, str::FromStr};

use clap::{Arg, ArgAction, ArgGroup, Command};
use generic_array::GenericArray;
use headers::{HeaderName, HeaderValue};
use ipnet::Ipv4Net;
use typenum::U32;
use zeroize::{DefaultIsZeroes, Zeroizing};

pub struct Config {
    pub interface_name: String,
    pub interface_address: Option<Ipv4Net>,
    pub instance_type: InstanceType,
    pub key: Option<Zeroizing<Key>>,
    pub headers: Option<Vec<(HeaderName, HeaderValue)>>,
    pub debug: bool,
}

#[derive(Clone, Copy)]
pub struct Key(pub GenericArray<u8, U32>);

impl Default for Key {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl DefaultIsZeroes for Key {}

pub enum InstanceType {
    Client(SocketAddr),
    Server(SocketAddr),
}

pub fn get_config() -> Config {
    let matches = Command::new("tcplink")
        .arg(
            Arg::new("interface-name")
                .long("interface")
                .short('i')
                .value_parser(clap::value_parser!(String))
                .required(true),
        )
        .arg(
            Arg::new("interface-address")
                .long("interface-address")
                .short('a')
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("listen")
                .long("listen")
                .short('l')
                .value_parser(clap::value_parser!(SocketAddr)),
        )
        .arg(
            Arg::new("connect")
                .long("connect")
                .short('c')
                .value_parser(clap::value_parser!(SocketAddr)),
        )
        .arg(
            Arg::new("key-file")
                .long("key-file")
                .short('k')
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .short('d')
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("http-proxy-header-value")
                .long("http-proxy-header-value")
                .short('H')
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append),
        )
        .group(
            ArgGroup::new("server-or-client")
                .args(["listen", "connect"])
                .required(true),
        )
        .arg_required_else_help(true)
        .get_matches();

    Config {
        interface_name: matches
            .get_one::<String>("interface-name")
            .unwrap()
            .to_owned(),
        interface_address: matches
            .get_one::<String>("interface-address")
            .map(|x| Ipv4Net::from_str(x).expect("Invalid IP address")),
        instance_type: matches
            .get_one::<SocketAddr>("listen")
            .map(|x| InstanceType::Server(*x))
            .unwrap_or_else(|| {
                InstanceType::Client(*matches.get_one::<SocketAddr>("connect").unwrap())
            }),
        key: matches.get_one::<PathBuf>("key-file").map(|x| {
            let mut key = GenericArray::clone_from_slice(&[0u8; 32]);
            std::fs::File::open(x)
                .expect("Failed to open keyfile for reading")
                .read_exact(key.as_mut_slice())
                .expect("Failed to read keyfile");
            Zeroizing::new(Key(key))
        }),
        headers: matches
            .get_many::<String>("http-proxy-header-value")
            .map(|x| {
                x.map(|x| {
                    let (name, value) = x
                        .split_once(':')
                        .expect("Invalid header value pair (expected `HeaderName: HeaderValue`)");

                    (
                        HeaderName::from_str(name).expect("Invalid header name"),
                        HeaderValue::from_str(value).expect("Invalid header value"),
                    )
                })
                .collect()
            }),
        debug: *matches.get_one::<bool>("debug").unwrap(),
    }
}
