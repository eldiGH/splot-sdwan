use std::collections::{BTreeMap, HashSet};

use crate::{
    config::Config,
    model::{
        host::{Host, HostRef},
        service::{Service, Wan},
        validator::{
            references::{Resolution, resolve_sources},
            types::ValidationReport,
            wan::{check_targets, warn_unused_wan_zones},
        },
    },
    types::{allow_from_ref::AllowFromRef, identifier::Identifier},
};

/// Builds every service whole while it checks it: the sources its `allowFrom`
/// lets in and, when it's exposed, what each `wan.via` node forwards it to (one
/// of its host's addresses, so this runs after the hosts are built).
pub(super) fn check_services(
    config: &Config,
    hosts: &[Host],
    known_references: &HashSet<AllowFromRef>,
    report: &mut ValidationReport,
) -> BTreeMap<HostRef, BTreeMap<Identifier, Service>> {
    let resolution = Resolution::of(config);
    let hosts: BTreeMap<&HostRef, &Host> = hosts.iter().map(|host| (host.id(), host)).collect();
    let mut wan_nodes_used = HashSet::new();
    let mut services: BTreeMap<HostRef, BTreeMap<Identifier, Service>> = BTreeMap::new();

    for (service, host) in config.services() {
        let (host_ref, name) = HostRef::of_service(host);

        let sources = resolve_sources(service, known_references, &resolution, report, |loc| {
            host.to_location(loc)
        });
        let wan = service.wan.as_ref().map(|wan| Wan {
            targets: check_targets(
                config,
                wan,
                host,
                hosts.get(&host_ref).copied(),
                &mut wan_nodes_used,
                report,
            ),
            sources: wan.sources.clone().into(),
        });

        services.entry(host_ref).or_default().insert(
            name.clone(),
            Service {
                port: service.port,
                proto: service.proto.clone().into(),
                sources,
                wan,
            },
        );
    }

    warn_unused_wan_zones(config, &wan_nodes_used, report);

    services
}
