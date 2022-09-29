use std::{net::SocketAddr, str::FromStr};

use clap::{Arg, ArgAction, ArgGroup, Command};
use headers::{HeaderName, HeaderValue};
use ipnet::Ipv4Net;

pub struct Config {
    pub interface_name: String,
    pub interface_address: Option<Ipv4Net>,
    pub instance_type: InstanceType,
    pub http_proxy: Option<HttpProxy>,
    pub debug: bool,
}

pub enum InstanceType {
    Client(SocketAddr),
    Server(SocketAddr),
}

pub struct HttpProxy {
    pub address: SocketAddr,
    pub user_pass: Option<(String, String)>,
    pub headers: Option<Vec<(HeaderName, HeaderValue)>>,
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
            Arg::new("debug")
                .long("debug")
                .short('d')
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("http-proxy-address")
                .long("http-proxy-address")
                .short('x')
                .value_parser(clap::value_parser!(SocketAddr))
                .conflicts_with("listen"),
        )
        .arg(
            Arg::new("http-proxy-username")
                .long("http-proxy-username")
                .short('u')
                .value_parser(clap::value_parser!(String))
                .requires("http-proxy-address")
                .requires("http-proxy-password"),
        )
        .arg(
            Arg::new("http-proxy-password")
                .long("http-proxy-password")
                .short('p')
                .value_parser(clap::value_parser!(String))
                .requires("http-proxy-address")
                .requires("http-proxy-username"),
        )
        .arg(
            Arg::new("http-proxy-header-value")
                .long("http-proxy-header-value")
                .short('H')
                .value_parser(clap::value_parser!(String))
                .action(ArgAction::Append)
                .requires("http-proxy-address"),
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
        http_proxy: matches
            .get_one::<SocketAddr>("http-proxy-address")
            .map(|address| HttpProxy {
                address: *address,
                user_pass: matches
                    .get_one::<String>("http-proxy-username")
                    .map(|username| {
                        (
                            username.to_owned(),
                            matches
                                .get_one::<String>("http-proxy-password")
                                .unwrap()
                                .to_owned(),
                        )
                    }),
                headers: matches
                    .get_many::<String>("http-proxy-header-value")
                    .map(|x| {
                        x.map(|x| {
                            let (name, value) = x.split_once(':').expect(
                                "Invalid header value pair (expected `HeaderName: HeaderValue`)",
                            );

                            (
                                HeaderName::from_str(name).expect("Invalid header name"),
                                HeaderValue::from_str(value).expect("Invalid header value"),
                            )
                        })
                        .collect()
                    }),
            }),
        debug: matches.contains_id("debug"),
    }
}
