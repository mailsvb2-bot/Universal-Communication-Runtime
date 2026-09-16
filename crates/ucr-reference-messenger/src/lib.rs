#![forbid(unsafe_code)]

//! Prepared Phase-40 Reference Messenger consumer boundary.
//!
//! This crate is deliberately outside the internal UCR workspace. It consumes only
//! `ucr-sdk`, so any Reference Messenger feature must be reachable through the public
//! contract rather than through hidden Core or storage APIs.

mod accessibility;
mod capability;
mod client;
mod presentation;

pub use accessibility::{AccessibilityContract, AccessibilityRequirement, TextDirection};
pub use capability::{ProofCapability, ProofItem, ProofState, phase40_proof_matrix};
pub use client::ReferenceMessengerClient;
pub use presentation::{PrimaryConcept, StatusIndicator, UiEventKey};
pub use ucr_sdk::{RpcStatus, ServiceCredential, TransportError, pb};
