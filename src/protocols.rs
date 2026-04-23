use serde::Deserialize;

#[derive(Deserialize, Hash, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Protocols {
    Tcp,
    Udp,
    Icmp,
}
