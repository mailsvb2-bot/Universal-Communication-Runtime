use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use ucr_core::RouteCandidate;

pub const LOCAL_TCP_CAPABILITY: &str = "ucr.transport.local.tcp";
pub const LOCAL_TCP_SCHEME: &str = "ucr.local.tcp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRouteError {
    UnsupportedCapability,
    UnsupportedScheme,
    InvalidAddressEncoding,
    InvalidSocketAddress,
    NonLocalDirectAddress,
    ZeroPort,
}

pub(crate) fn local_socket_addr(route: &RouteCandidate) -> Result<SocketAddr, LocalRouteError> {
    if route.transport_capability != LOCAL_TCP_CAPABILITY {
        return Err(LocalRouteError::UnsupportedCapability);
    }
    if route.address.scheme != LOCAL_TCP_SCHEME {
        return Err(LocalRouteError::UnsupportedScheme);
    }
    let value = core::str::from_utf8(&route.address.value)
        .map_err(|_| LocalRouteError::InvalidAddressEncoding)?;
    let socket = SocketAddr::from_str(value).map_err(|_| LocalRouteError::InvalidSocketAddress)?;
    if socket.port() == 0 {
        return Err(LocalRouteError::ZeroPort);
    }
    if !is_local_direct_ip(socket.ip()) {
        return Err(LocalRouteError::NonLocalDirectAddress);
    }
    Ok(socket)
}

pub(crate) fn is_local_direct_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_local_ipv4(ip),
        IpAddr::V6(ip) => is_local_ipv6(ip),
    }
}

fn is_local_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 127
        || a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
}

fn is_local_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_local_ipv4(ipv4);
    }
    if ip.is_loopback() {
        return true;
    }
    let first = ip.segments()[0];
    first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use ucr_model::{EndpointAddress, EndpointId, OpaqueId};

    use super::*;

    fn route(address: &str) -> RouteCandidate {
        RouteCandidate {
            endpoint_id: EndpointId::from_opaque(OpaqueId::new("peer-endpoint").expect("id")),
            transport_capability: LOCAL_TCP_CAPABILITY.to_owned(),
            address: EndpointAddress {
                scheme: LOCAL_TCP_SCHEME.to_owned(),
                value: address.as_bytes().to_vec(),
            },
        }
    }

    #[test]
    fn loopback_private_and_link_local_literals_are_accepted() {
        for value in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "172.16.0.1:443",
            "172.31.255.254:443",
            "192.168.1.1:443",
            "169.254.1.1:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fd12:3456::1]:443",
            "[fe80::1]:443",
        ] {
            assert!(local_socket_addr(&route(value)).is_ok(), "rejected {value}");
        }
    }

    #[test]
    fn public_cgnat_documentation_multicast_unspecified_and_dns_fail_closed() {
        for value in [
            "8.8.8.8:443",
            "100.64.0.1:443",
            "192.0.2.1:443",
            "198.51.100.2:443",
            "203.0.113.3:443",
            "224.0.0.1:443",
            "0.0.0.0:443",
            "[2001:4860:4860::8888]:443",
            "[2001:db8::1]:443",
            "[ff02::1]:443",
            "[::]:443",
            "example.local:443",
        ] {
            assert!(local_socket_addr(&route(value)).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn capability_scheme_and_port_are_exact() {
        let mut wrong_capability = route("192.168.1.2:443");
        wrong_capability.transport_capability = "ucr.transport.internet.tcp".to_owned();
        assert_eq!(
            local_socket_addr(&wrong_capability),
            Err(LocalRouteError::UnsupportedCapability)
        );

        let mut wrong_scheme = route("192.168.1.2:443");
        wrong_scheme.address.scheme = "ucr.internet.tcp".to_owned();
        assert_eq!(
            local_socket_addr(&wrong_scheme),
            Err(LocalRouteError::UnsupportedScheme)
        );

        assert_eq!(
            local_socket_addr(&route("192.168.1.2:0")),
            Err(LocalRouteError::ZeroPort)
        );
    }
}
