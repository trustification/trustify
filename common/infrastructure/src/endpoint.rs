use std::fmt::Debug;
use url::Url;

pub trait Endpoint: Debug {
    const PORT: u16;
    const PATH: &'static str;

    fn port() -> u16 {
        Self::PORT
    }

    fn url() -> Url {
        Url::parse(&format!("http://localhost:{}{}", Self::PORT, Self::PATH))
            .expect("default value must parse")
    }
}

use std::ffi::OsString;
use std::marker::PhantomData;
use std::net::{AddrParseError, SocketAddr};
use std::str::FromStr;

use clap::{
    value_parser, Arg, ArgMatches, Args, Command, CommandFactory, Error, FromArgMatches, Parser,
};

#[derive(Clone, Debug)]
pub struct EndpointServerConfig<E: Endpoint> {
    pub bind: String,
    pub port: u16,

    _marker: PhantomData<E>,
}

impl<E: Endpoint> EndpointServerConfig<E> {
    pub fn new(bind: &str, port: u16) -> Self {
        Self {
            bind: bind.to_string(),
            port,
            _marker: Default::default(),
        }
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, AddrParseError> {
        SocketAddr::from_str(&format!("{}:{}", self.bind, self.port))
    }
}

impl<E: Endpoint> FromArgMatches for EndpointServerConfig<E> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, Error> {
        Ok(Self {
            bind: matches
                .get_one::<String>("bind")
                .cloned()
                .unwrap_or("0.0.0.0".into()),
            port: matches.get_one::<u16>("port").cloned().unwrap_or(E::port()),
            _marker: PhantomData,
        })
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), Error> {
        if let Some(bind) = matches.get_one::<String>("bind") {
            self.bind = bind.clone()
        }

        if let Some(port) = matches.get_one::<u16>("port") {
            self.port = *port;
        }
        Ok(())
    }
}

impl<E: Endpoint> Args for EndpointServerConfig<E> {
    fn augment_args(cmd: Command) -> Command {
        Self::augment_args_for_update(cmd)
    }

    fn augment_args_for_update(cmd: Command) -> Command {
        cmd.next_help_heading("API")
            .arg(
                Arg::new("bind")
                    .short('b')
                    .long("bind")
                    .default_value("0.0.0.0"),
            )
            .arg(
                Arg::new("port")
                    .short('p')
                    .long("port")
                    .value_parser(value_parser!(u16))
                    .default_value(OsString::from(format!("{}", E::port()))),
            )
    }
}

impl<E: Endpoint> CommandFactory for EndpointServerConfig<E> {
    fn command() -> Command {
        todo!()
    }

    fn command_for_update() -> Command {
        todo!()
    }
}

impl<E: Endpoint> Parser for EndpointServerConfig<E> {}

macro_rules! endpoint {
    ($name: ident) => {
        #[derive(Debug)]
        pub struct $name;
        impl Endpoint for $name {
            const PORT: u16 = 0;
            const PATH: &'static str = "";
        }
    };

    ($name: ident, $port: literal) => {
        #[derive(Debug)]
        pub struct $name;
        impl Endpoint for $name {
            const PORT: u16 = $port;
            const PATH: &'static str = "";
        }
    };

    ($name: ident, $port: literal, $path: literal) => {
        #[derive(Debug)]
        pub struct $name;
        impl Endpoint for $name {
            const PORT: u16 = $port;
            const PATH: &'static str = $path;
        }
    };
}

endpoint!(Huevos, 8080);
