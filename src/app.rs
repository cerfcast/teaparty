use std::net::{IpAddr, Ipv4Addr};

use clap::{Args, Parser, Subcommand};

use crate::{
    ip::{DscpValue, EcnValue},
    meta::MetaSocketAddr,
    stamp::{Ssid, StampError},
    HeartbeatConfiguration, Ipv6ExtensionHeaderArg, MalformedWhy,
};

#[allow(dead_code)]
#[derive(Debug)]
pub enum ClientError {
    Cli(clap::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum TeapartyError {
    Client(ClientError),
    Stamp(StampError),
}

impl From<StampError> for TeapartyError {
    fn from(value: StampError) -> Self {
        TeapartyError::Stamp(value)
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(default_value_t=IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))]
    pub ip_addr: IpAddr,

    #[arg(default_value_t = 862)]
    pub port: u16,

    /// Specify the verbosity of output. Repeat to increase loquaciousness
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,

    /// Specify the file to which log information should be written (defaults to terminal)
    #[arg(long, value_parser = clap::value_parser!(clio::ClioPath))]
    pub log_output: Option<clio::ClioPath>,
}

#[derive(Args, Debug)]
pub struct SenderArgs {
    /// Specify a non-zero Ssid (in decimal or hexadecimal [by using the 0x prefix])
    #[arg(long)]
    pub ssid: Option<Ssid>,

    /// Include a malformed Tlv in the test packet
    #[arg(long)]
    pub malformed: Option<MalformedWhy>,

    /// Enable a non-default ECN for testing
    #[arg(long)]
    pub ecn: Option<EcnValue>,

    /// Enable a non-default DSCP for testing
    #[arg(long)]
    pub dscp: Option<DscpValue>,

    /// Enable a non-default TTL for testing
    #[arg(long)]
    pub ttl: Option<u8>,

    /// Enable a non-operating-system chosen source port for the test packet
    #[arg(long)]
    pub src_port: Option<u16>,

    #[arg(long)]
    pub authenticated: Option<String>,

    /// Add an IPv6 Extension Header option to the Destination Extension Header (specified as T,L[,V])
    #[arg(long)]
    pub destination_ext: Vec<Ipv6ExtensionHeaderArg>,

    /// Add an IPv6 Extension Header option to the Hop-by-hop Extension Header (specified as T,L[,V])
    #[arg(long)]
    pub hbh_ext: Vec<Ipv6ExtensionHeaderArg>,
}

#[derive(Args, Debug)]
pub struct ReflectorArgs {
    #[arg(
        long,
        default_value_t = false,
        help = "Run teaparty in stateless mode."
    )]
    pub stateless: bool,

    #[arg(long, action = clap::ArgAction::Append, help = "Specify heartbeat message target and interval (in seconds) as [IP:PORT]@[Seconds]")]
    pub heartbeat: Vec<HeartbeatConfiguration>,

    #[arg(
        long,
        default_value_t = false,
        help = "Run teaparty in link-layer mode."
    )]
    pub link_layer: bool,

    #[arg(
        long,
        help = "Specify the address (either as simply an IP or IP:PORT) on which the meta RESTful interface will listen (by default, meta interface will be on the same address as STAMP on port 8000)"
    )]
    pub meta_addr: Option<MetaSocketAddr>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Sender(SenderArgs),
    Reflector(ReflectorArgs),
}
