use ipnet::Ipv4Net;
use jiff::Span;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub bridge: BridgeConfig,
    pub device: Vec<DeviceConfig>,
    pub nat: Option<NatConfig>,
}

#[derive(Deserialize)]
pub struct BridgeConfig {
    pub name: String,
    pub cidr: Ipv4Net,
}

#[derive(Deserialize)]
pub struct DeviceConfig {
    pub node: String,
    pub name: String,
    pub cidr: Ipv4Net,

    #[serde(default)]
    pub delay: Span,

    #[serde(default)]
    pub jitter: Span,
}

#[derive(Deserialize)]
pub struct NatConfig {
    pub device: String,
    pub cidr: Ipv4Net,
}

impl DeviceConfig {
    pub fn namespace(&self) -> String {
        format!("ns-{}", self.name)
    }

    pub fn device(&self) -> String {
        format!("dev-{}", self.name)
    }
}
