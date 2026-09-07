use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use ucr_core::RouteCandidate;

pub const INTERNET_TCP_CAPABILITY: &str = "ucr.transport.internet.tcp";
pub const INTERNET_TCP_SCHEME: &str = "ucr.internet.tcp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternetRouteError {
    UnsupportedCapability,
    UnsupportedScheme,
    InvalidAddressEncoding,
    InvalidSocketAddress,
    NonPublicInternetAddress,
    ZeroPort,
}

pub(crate) fn public_socket_addr(route: &RouteCandidate) -> Result<SocketAddr, InternetRouteError> {
    parse_route_socket_addr(route, false)
}

#[cfg(test)]
pub(crate) fn test_socket_addr(route: &RouteCandidate) -> Result<SocketAddr, InternetRouteError> {
    parse_route_socket_addr(route, true)
}

fn parse_route_socket_addr(
    route: &RouteCandidate,
    allow_loopback_for_tests: bool,
) -> Result<SocketAddr, InternetRouteError> {
    if route.transport_capability != INTERNET_TCP_CAPABILITY {
        return Err(InternetRouteError::UnsupportedCapability);
    }
    if route.address.scheme != INTERNET_TCP_SCHEME {
        return Err(InternetRouteError::UnsupportedScheme);
    }
    let value = core::str::from_utf8(&route.address.value)
        .map_err(|_| InternetRouteError::InvalidAddressEncoding)?;
    let socket =
        SocketAddr::from_str(value).map_err(|_| InternetRouteError::InvalidSocketAddress)?;
    if socket.port() == 0 {
        return Err(InternetRouteError::ZeroPort);
    }
    if allow_loopback_for_tests && socket.ip().is_loopback() {
        return Ok(socket);
    }
    if !is_public_internet_ip(socket.ip()) {
        return Err(InternetRouteError::NonPublicInternetAddress);
    }
    Ok(socket)
}

pub(crate) fn is_public_internet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && b == 168 {
        return false;
    }
    if a == 192 && b == 0 && c == 0 {
        return false;
    }
    if a == 192 && b == 0 && c == 2 {
        return false;
    }
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let segments = ip.segments();
    if segments[0] & 0xfe00 == 0xfc00 || segments[0] & 0xffc0 == 0xfe80 {
        return false;
    }
    if segments[0] & 0xffc0 == 0xfec0 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    segments[0] & 0xe000 == 0x2000
}

#[cfg(test)]
mod tests {
    use ucr_model::{EndpointAddress, EndpointId, OpaqueId};

    use super::*;

    fn route(address: &str) -> RouteCandidate {
        RouteCandidate {
            endpoint_id: EndpointId::from_opaque(OpaqueId::new("peer-endpoint").expect("id")),
            transport_capability: INTERNET_TCP_CAPABILITY.to_owned(),
            address: EndpointAddress {
                scheme: INTERNET_TCP_SCHEME.to_owned(),
                value: address.as_bytes().to_vec(),
            },
        }
    }

    #[test]
    fn public_literal_ipv4_and_ipv6_are_accepted() {
        assert_eq!(
            public_socket_addr(&route("8.8.8.8:443")).expect("ipv4"),
            "8.8.8.8:443".parse().expect("socket")
        );
        assert!(public_socket_addr(&route("[2606:4700:4700::1111]:443")).is_ok());
    }

    #[test]
    fn loopback_private_documentation_and_dns_names_fail_closed() {
        for value in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "100.64.0.1:443",
            "169.254.1.1:443",
            "172.16.0.1:443",
            "192.168.1.1:443",
            "192.0.2.1:443",
            "198.51.100.2:443",
            "203.0.113.3:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[2001:db8::1]:443",
            "example.com:443",
        ] {
            assert!(
                public_socket_addr(&route(value)).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn test_path_allows_only_loopback_exception() {
        assert!(test_socket_addr(&route("127.0.0.1:65000")).is_ok());
        assert_eq!(
            test_socket_addr(&route("192.168.1.2:65000")),
            Err(InternetRouteError::NonPublicInternetAddress)
        );
    }
}
