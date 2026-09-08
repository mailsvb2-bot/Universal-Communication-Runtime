mod handshake;
mod local;
mod local_handshake;
mod local_route;
mod provider;
mod route;
mod wire;

pub use handshake::{
    InternetHandshakeError, InternetPeerExpectation, InternetPeerExpectationError,
    InternetPeerExpectationResolver, InternetTransportIdentity,
};
pub use handshake::{
    InternetPeerExpectation as LocalPeerExpectation,
    InternetPeerExpectationError as LocalPeerExpectationError,
    InternetPeerExpectationResolver as LocalPeerExpectationResolver,
};
pub use local::{
    LocalAcceptStatus, LocalEnvelopeSink, LocalSinkError, LocalTransportConfigError,
    LocalTransportMetrics, LocalTransportPolicy, LocalTransportProvider, LocalTransportServer,
};
pub use local_handshake::{LOCAL_CONTEXT_EXTENSION, LocalHandshakeError, LocalTransportIdentity};
pub use local_route::{LOCAL_TCP_CAPABILITY, LOCAL_TCP_SCHEME, LocalRouteError};
pub use provider::{
    InternetAcceptStatus, InternetEnvelopeSink, InternetSinkError, InternetTransportConfigError,
    InternetTransportMetrics, InternetTransportPolicy, InternetTransportProvider,
    InternetTransportServer,
};
pub use route::{INTERNET_TCP_CAPABILITY, INTERNET_TCP_SCHEME, InternetRouteError};

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_untrusted_internet_frame(bytes: &[u8]) {
    wire::fuzz_decode_untrusted_internet_frame(bytes);
}
