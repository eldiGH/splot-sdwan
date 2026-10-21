//! The checked types the config is read into. Those the agent on a node reads
//! too live in `splot-core`, and are used from here as if they were here.

pub use splot_core::{identifier, wg_key};

pub mod allow_from_ref;
pub mod config_location;
pub mod endpoint;
pub mod ip;
pub mod mac;
pub mod platform;
pub mod port;
pub mod protocol;
pub mod schema_helpers;
pub mod wan_via_target;

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fmt::Display, str::FromStr};

    use super::{
        allow_from_ref::AllowFromRef,
        endpoint::{EndpointHost, Hostname},
        identifier::{Identifier, NestedIdentifier},
        ip::{Ipv4Interface, Ipv4Network},
        mac::MacAddress,
        platform::{FirewallProgram, Os, Setting},
        port::{Port, PortOrRange, PortRange, ServicePort},
        schema_helpers::OneOrManyUnique,
        wan_via_target::{WanViaTarget, WanViaTargets},
    };

    /// `input` parsed as a `T`, which fails: `T: input → message`.
    fn error<T: FromStr>(input: &str) -> String
    where
        T::Err: Display,
    {
        let Err(err) = input.parse::<T>() else {
            panic!("{input:?} parsed as a {}", std::any::type_name::<T>());
        };
        // Without module paths: `Setting<FirewallProgram>`.
        let name: Vec<&str> = std::any::type_name::<T>()
            .split('<')
            .map(|part| part.rsplit("::").next().unwrap())
            .collect();
        let name = name.join("<");

        format!("{name}: {input:?} → {err}")
    }

    #[test]
    fn every_parse_error_is_a_std_error() {
        // Fails to compile, not to run, when one isn't.
        fn is_error<E: std::error::Error>() {}

        is_error::<super::ip::ParseCidrError>();
        is_error::<super::ip::Ipv4InterfaceError>();
        is_error::<super::ip::Ipv4NetworkError>();
        is_error::<super::port::ParsePortError>();
        is_error::<super::port::ParsePortRangeError>();
        is_error::<super::port::ParsePortOrRangeError>();
        is_error::<super::port::ParseServicePortError>();
        is_error::<super::identifier::ParseIdentifierError>();
        is_error::<super::identifier::ParseNestedIdentifierError>();
        is_error::<super::allow_from_ref::ParseAllowFromRefError>();
        is_error::<super::wan_via_target::ParseWanViaTargetError>();
        is_error::<super::wan_via_target::ParseWanViaTargetsError>();
        is_error::<super::mac::ParseMacError>();
        is_error::<super::endpoint::ParseHostnameError>();
        is_error::<super::endpoint::ParseEndpointHostError>();
        is_error::<super::wg_key::KeyFormatError>();
        is_error::<super::platform::ParseSettingError>();
        is_error::<splot_core::os::ParseOsError>();
        is_error::<crate::model::validator::types::ValidationError>();
        is_error::<splot_agent::process::Error>();
    }

    #[test]
    fn every_parse_error_message() {
        // Pins what each one says, as the config's reader sees it.
        let long_label = "a".repeat(64);
        let long_name = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(62));
        let messages = [
            error::<Ipv4Network>("10.0.0.1"),
            error::<Ipv4Network>("10.0.0.0/33"),
            error::<Ipv4Network>("10.0.0.300/24"),
            error::<Ipv4Network>("10.0.0.1/24"),
            error::<Ipv4Interface>("10.0.0.0/24"),
            error::<Ipv4Interface>("10.0.0.255/24"),
            error::<Ipv4Interface>("x/24"),
            error::<Port>("x"),
            error::<Port>("0"),
            error::<PortRange>("x-80"),
            error::<PortRange>("80-22"),
            error::<PortRange>("80"),
            error::<PortOrRange>("x"),
            error::<PortOrRange>("80-22"),
            error::<ServicePort>("x"),
            error::<ServicePort>("80-22"),
            error::<ServicePort>("1000-1010:2000-2005"),
            error::<ServicePort>("80:1000-1010"),
            error::<Identifier>(""),
            error::<Identifier>("a b"),
            error::<Identifier>("spl_x"),
            error::<NestedIdentifier>("abc"),
            error::<NestedIdentifier>("a.b.c"),
            error::<NestedIdentifier>(".b"),
            error::<NestedIdentifier>("a.b c"),
            error::<AllowFromRef>("a b"),
            error::<AllowFromRef>("a.b.c"),
            error::<WanViaTarget>("a b"),
            error::<WanViaTarget>("a.b.c"),
            error::<MacAddress>("gg:bb:cc:dd:ee:ff"),
            error::<MacAddress>("aa:bb"),
            error::<MacAddress>("aa|bb|cc|dd|ee|ff"),
            error::<MacAddress>("aa:bb-cc:dd:ee:ff"),
            error::<Hostname>(&long_name),
            error::<Hostname>("a..b"),
            error::<Hostname>(&format!("{long_label}.net")),
            error::<Hostname>("a_b.net"),
            error::<Hostname>("-a.net"),
            error::<Hostname>("10.0.0.300"),
            error::<EndpointHost>("a_b.net"),
            error::<Setting<FirewallProgram>>("iptables"),
            error::<Os>("windows"),
        ];

        // wan.via names a node at most once; only serde builds that list.
        let via: BTreeSet<WanViaTarget> = ["Home", "Home.lan"]
            .into_iter()
            .map(|target| target.parse().unwrap())
            .collect();
        let duplicate = WanViaTargets::try_from(OneOrManyUnique(via)).unwrap_err();

        insta::assert_snapshot!(format!(
            "{}\nWanViaTargets: [Home, Home.lan] → {duplicate}",
            messages.join("\n")
        ));
    }
}
