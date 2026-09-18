# ADR 0104: Licensing boundary preserves no unintended grant

Status: Accepted

## Context

The Canon requires the licensing boundary for Protocol, Core, SDKs, Reference Client, Managed Infrastructure and Enterprise Features to be defined before a public release. The repository is publicly visible but currently contains no publisher-approved general software license grant.

Choosing an open-source, source-available or commercial grant on behalf of the publisher would be a business/legal decision outside an implementation task. The architecture must nevertheless have an explicit fail-closed boundary.

## Decision

For the Production 1.0 baseline:

- Protocol/specification publication is an interoperability/specification surface; repository visibility alone is not a software copyright license grant.
- Core, SDKs and Reference Client receive no general redistribution/relicensing grant merely from this ADR or repository visibility. Any distributed release that is intended for third-party reuse must carry publisher-approved license text.
- Managed Infrastructure and Enterprise Features are separate commercial/service licensing surfaces by default and are not required to share the same distribution terms as the public protocol contract.
- Licensing checks never alter wire semantics, canonical Identity/Message/Conversation ownership or interoperability.
- A future publisher-approved OSS/source-available/commercial license decision supersedes this ADR explicitly and adds the corresponding license artifacts; no code fork is required.

General public redistribution is therefore fail-closed until explicit publisher-approved license text accompanies the release. Publisher-controlled/internal deployment is not reclassified as generally licensed software.

## Consequences

This closes the architectural licensing boundary without inventing a legal grant. It preserves future commercialization while preventing accidental assumptions that “public repository” means unrestricted reuse.
