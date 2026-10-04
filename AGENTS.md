# UCR Agent / Operator Safety Policy

## Server access prohibition

For this repository, all work is GitHub/repository-local by default.

It is **forbidden** to access, inspect, connect to, modify, deploy to, clean, restart, configure, or otherwise interact with **any server, VM, VPS, remote host, SSH target, production machine, staging machine, or other remote computer** unless the project owner explicitly identifies that exact server for this project in a future instruction.

This prohibition includes, without limitation:

- SSH or SCP access;
- remote shell / terminal commands;
- deployments or production rollouts;
- disk cleanup or filesystem inspection;
- service, container, process, database, firewall, reverse-proxy, DNS, TLS, or operating-system changes;
- using a server remembered from another conversation, project, environment, document, repository, credential set, or prior deployment;
- inferring that a known server belongs to UCR;
- treating an unspecified "server", "production", "staging", or "deploy" target as authorization.

### Required authorization

Server interaction is allowed only after the owner explicitly provides or identifies the specific server/host to use for UCR. Authorization for one server does **not** authorize any other server and does not carry over from another project.

If no exact server has been explicitly designated, remain on GitHub/repository work only.

This rule overrides convenience, prior knowledge, inferred infrastructure, and historical project context.
