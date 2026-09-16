/// Primary concepts that the Reference Messenger may expose to ordinary users.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryConcept {
    Person,
    Group,
    Message,
    Call,
    Result,
}

/// User-facing status concepts. Transport implementation names are intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusIndicator {
    SecureCommunication,
    IdentityVerified,
    DirectCommunication,
    ExternalService,
    PartiallyLimited,
    AwaitingDeliveryOpportunity,
}

/// Localization keys emitted by the presentation layer instead of baked human-readable text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiEventKey {
    IdentityVerified,
    NewDeviceObserved,
    DeviceNoLongerTrusted,
    ConversationProtectionChanged,
    AwaitingDeliveryOpportunity,
}
