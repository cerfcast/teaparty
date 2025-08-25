use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr},
};

use clap::{Args, Parser, Subcommand};
use clio::ClioPath;
use yaml_rust2::{Yaml, YamlLoader};

use crate::{
    ip::{DscpValue, EcnValue},
    meta::MetaSocketAddr,
    stamp::{Ssid, StampError},
    HeartbeatConfiguration, Ipv6ExtensionHeaderArg, MalformedWhy,
};

#[derive(Debug)]
pub enum ClientError {
    Cli(clap::Error),
}

#[derive(Debug)]
pub enum ServerError {
    Cli(clap::Error),
    Config(String),
    Runtime(String),
}

#[derive(Debug)]
pub enum TeapartyError {
    Client(ClientError),
    Server(ServerError),
    Stamp(StampError),
}

impl From<StampError> for TeapartyError {
    fn from(value: StampError) -> Self {
        TeapartyError::Stamp(value)
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Specify the verbosity of output. Repeat to increase loquaciousness
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,

    /// Specify the file to which log information should be written (defaults to terminal)
    #[arg(long, value_parser = clap::value_parser!(clio::ClioPath))]
    pub log_output: Option<clio::ClioPath>,
}

#[derive(Clone, Args, Debug)]
pub struct SenderArgs {
    #[arg(default_value_t=IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))]
    pub ip_addr: IpAddr,

    #[arg(default_value_t = 862)]
    pub port: u16,

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
    /// Specify the file to which log information should be written (defaults to terminal)
    #[arg(long, value_parser = clap::value_parser!(clio::ClioPath))]
    pub config: Option<clio::ClioPath>,
}

#[derive(Default, Debug, Clone)]
pub struct ReflectorTlvConfiguration {
    pub tlv: String,
    pub configuration: Option<Yaml>,
}

#[derive(Default, Debug, Clone)]
pub struct ReflectorTlvConfigurations {
    configurations: Vec<ReflectorTlvConfiguration>,
}

#[derive(Default, Clone, Debug)]
pub struct ReflectorGeneralConfiguration {
    pub stateless: bool,

    pub heartbeat: Vec<HeartbeatConfiguration>,

    pub link_layer: bool,

    pub meta_addr: Option<MetaSocketAddr<8000>>,

    pub listen_addr: MetaSocketAddr<862>,

    pub reflector_tlv_configurations: ReflectorTlvConfigurations,

    pub name: Option<String>,
}

impl TryFrom<&Yaml> for ReflectorGeneralConfiguration {
    type Error = TeapartyError;

    fn try_from(value: &Yaml) -> Result<Self, Self::Error> {
        let mut reflector_configuration = ReflectorGeneralConfiguration::default();
        // Each instance should be a hash with a single key/value pair ...
        if let Some(config_yaml) = value.as_vec() {
            for config_section in config_yaml {
                if let Some(config_section) = config_section.as_hash() {
                    for (config_section_title, config_section) in config_section {
                        if *config_section_title == Yaml::String("general".to_string()) {
                            if let Some(general_configuration_hash) = config_section.as_hash() {
                                // If there is a name, try to use it.
                                if let Some(maybe_name) = general_configuration_hash
                                    .get(&Yaml::String("name".to_string()))
                                {
                                    if let Some(name) = maybe_name.as_str() {
                                        reflector_configuration.name = Some(name.to_string());
                                    } else {
                                        return Err(TeapartyError::Server(
                                                            ServerError::Config("Error parsing name configuration: value was not a string".to_string())));
                                    }
                                }

                                // If there is a stateless, try to use it.
                                if let Some(maybe_stateless) = general_configuration_hash
                                    .get(&Yaml::String("stateless".to_string()))
                                {
                                    if let Some(stateless) = maybe_stateless.as_bool() {
                                        reflector_configuration.stateless = stateless;
                                    } else {
                                        return Err(TeapartyError::Server(
                                                            ServerError::Config("Error parsing stateless configuration: value was not a boolean".to_string())));
                                    }
                                }

                                // If there is a heartbeat, try to use it.
                                reflector_configuration.heartbeat =
                                    if let Some(maybe_heartbeat_configurations) =
                                        general_configuration_hash
                                            .get(&Yaml::String("heartbeat".to_string()))
                                    {
                                        if let Some(maybe_heartbeat_configurations) =
                                            maybe_heartbeat_configurations.as_vec()
                                        {
                                            let mut config: Vec<HeartbeatConfiguration> = vec![];

                                            for maybe_heartbeat_configuration in
                                                maybe_heartbeat_configurations
                                            {
                                                match maybe_heartbeat_configuration
                                                    .as_str()
                                                    .unwrap_or_default()
                                                    .parse::<HeartbeatConfiguration>()
                                                {
                                                    Err(e) => {
                                                        return Err(TeapartyError::Server(
                                                            ServerError::Config(format!(
                                                    "Error parsing heartbeat configuration: {e}"
                                                )),
                                                        ))
                                                    }
                                                    Ok(heartbeat_config) => {
                                                        config.push(heartbeat_config)
                                                    }
                                                }
                                            }

                                            config
                                        } else {
                                            vec![]
                                        }
                                    } else {
                                        vec![]
                                    };

                                reflector_configuration.link_layer = general_configuration_hash
                                    .get(&Yaml::String("link_layer".to_string()))
                                    .unwrap_or(&Yaml::Boolean(false))
                                    .clone()
                                    .into_bool()
                                    .unwrap_or_default();

                                reflector_configuration.meta_addr = if let Some(maybe_meta_addr) =
                                    general_configuration_hash
                                        .get(&Yaml::String("meta_addr".to_string()))
                                {
                                    Some(maybe_meta_addr.try_into()?)
                                } else {
                                    None
                                };

                                if let Some(maybe_listen_addr) = general_configuration_hash
                                    .get(&Yaml::String("listen".to_string()))
                                {
                                    reflector_configuration.listen_addr =
                                        maybe_listen_addr.try_into()?
                                }
                            }
                        } else {
                            // TLV
                        }
                    }
                } else {
                    return Err(TeapartyError::Server(ServerError::Config(
                        "Section of a reflector configuration is not a hash".into(),
                    )));
                }
            }
            Ok(reflector_configuration)
        } else {
            Err(TeapartyError::Server(ServerError::Config(
                "Configuration of reflector must be a sequence of hashes".into(),
            )))
        }
    }
}

pub fn extract_configuration(config_path: ClioPath) -> Result<Yaml, TeapartyError> {
    let mut file = config_path
        .open()
        .map_err(|e| TeapartyError::Server(ServerError::Config(e.to_string())))?;

    let mut config_contents: Vec<u8> = vec![];
    file.read_to_end(&mut config_contents).map_err(|e| {
        TeapartyError::Server(ServerError::Config(format!(
            "Could not read the contents of the config file: {e}"
        )))
    })?;

    let config_contents = TryInto::<String>::try_into(config_contents).map_err(|e| {
        TeapartyError::Server(ServerError::Config(format!(
            "Could not read the contents of the config file: {e}"
        )))
    })?;

    let config_contents = YamlLoader::load_from_str(&config_contents).map_err(|e| {
        TeapartyError::Server(ServerError::Config(format!(
            "Could not read the contents of the config file: {e}"
        )))
    })?;

    if config_contents.len() > 1 {
        Err(TeapartyError::Server(ServerError::Config(
            "Config file may only contain a single YAML document".into(),
        )))
    } else {
        Ok(config_contents[0].clone())
    }
}

#[derive(Subcommand, Debug)]
pub enum TeapartyModes {
    Sender(SenderArgs),
    Reflector(ReflectorArgs),
}
