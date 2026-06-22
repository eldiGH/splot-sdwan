use crate::types::identifier::Identifier;

pub enum ConfigLocation {
    MeshNetwork,
    Node(Identifier, Node(NodeLoc), Client(ClientLoc))
}

pub enum NodeLoc { Root, ListenPort, MeshIp, WanZone, Service(Identifier, ServiceLoc), Zone(Identifier, ZoneLoc), VpnInterface(Identifier, VpnLoc),  }
pub enum ZoneLoc { Root,  }
pub enum DeciceLoc {  }
pub enum ServiceLoc {  }
pub enum VpnLoc {  }
