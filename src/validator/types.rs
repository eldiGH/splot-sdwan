use std::net::Ipv4Addr;

use crate::types::ip::Ipv4Network;

#[derive(Clone)]
pub struct ConfigPath(Vec<String>);

impl ConfigPath {
    pub fn new(segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(segments.into_iter().map(|item| item.into()).collect())
    }

    pub fn extend(mut self, segments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.0.extend(segments.into_iter().map(|item| item.into()));
        self
    }
}

pub enum ValidationError {
    // names
    GlobalNameCollision {
        name: String,
        at: ConfigPath,
    },
    LocalNameCollision {
        name: String,
        at: ConfigPath,
    },
    InvalidName {
        name: String,
        at: ConfigPath,
    },
    InvalidPrefix {
        name: String,
        prefix: String,
        at: ConfigPath,
    },

    // tags
    InvalidTagName {
        tag: String,
        at: ConfigPath,
    },
    TagWithNameCollision {
        tag: String,
        at: ConfigPath,
    },

    // identifiers
    UnknownIdentifier {
        identifier: String,
        at: ConfigPath,
    },

    // networks
    IpOutsideSubnet {
        ip: Ipv4Addr,
        network: Ipv4Network,
        at: ConfigPath,
    },
    NetworkCollision {
        network: Ipv4Network,
        conflicting_with: Ipv4Network,
        at: ConfigPath,
    },
    IpCollision {
        ip: Ipv4Addr,
        at: ConfigPath,
        with: ConfigPath,
    },
    NodeClientManyZones {
        zone_name: String,
        existing_zone: ConfigPath,
        at: ConfigPath,
    },

    // entities
    MacMissing {
        at: ConfigPath,
    },

    PublicKeyMissing {
        required_for_mesh: bool,
        required_for_vpn_interface: bool,
        at: ConfigPath,
    },

    NodeMissing {
        node_name: String,
        at: ConfigPath,
    },

    NodeNetworkMissing {
        node_name: String,
        network_name: String,
        at: ConfigPath,
    },

    ClientIpInAddresslessZone {
        client_name: String,
        zone_name: String,
        at: ConfigPath,
    },

    DevicesInAddresslessZone {
        node_name: String,
        zone_name: String,
        at: ConfigPath,
    },

    // ports
    PortCollision {
        port: u16,
        at: ConfigPath,
        with: ConfigPath,
    },
}

pub enum ValidationWarning {
    // entities
    UnusedMac { at: ConfigPath },

    UnusedPublicKey { at: ConfigPath },

    UnreachableClient { at: ConfigPath },

    // identifiers
    ServiceAllowFromEmpty { at: ConfigPath },
}

#[derive(Default)]
pub struct ValidationReport {
    pub warnings: Vec<ValidationWarning>,
    pub errors: Vec<ValidationError>,
}
