use ipnet::Ipv4Net;
use jiff::Span;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub bridge: BridgeConfig,
    pub device: Vec<DeviceConfig>,
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

impl DeviceConfig {
    pub fn namespace(&self) -> String {
        format!("ns-{}", self.name)
    }

    pub fn device(&self) -> String {
        format!("dev-{}", self.name)
    }
}
