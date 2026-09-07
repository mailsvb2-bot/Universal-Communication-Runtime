mod handshake;
mod provider;
mod route;
mod wire;

pub use handshake::{
    InternetHandshakeError, InternetPeerExpectation, InternetPeerExpectationError,
    InternetPeerExpectationResolver, InternetTransportIdentity,
};
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
