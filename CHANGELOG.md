# Changelog

Notable changes to pipesix. The wire protocol remains version 5.

## 2.5.0 — 2026-11-27

### Added

- POSIX control-channel role-based access control with three roles:
  `viewer` for read-only inspection, `operator` for kick/reload, and `admin`
  for credentials, limits, lifecycle and accounting changes.
- `control_group`, `control_admin_group` and `control_operator_group`
  configuration. The socket is owner-only when no group is configured and
  becomes group-accessible with mode `0660` when `control_group` is set.
- Peer identity checks with `SO_PEERCRED` on Linux and `getpeereid()` on
  macOS/BSD, plus the same role matrix for direct CLI mutations and reloads.
- Actor-attributed audit records with `actor`, `actor_uid`, `role` and
  `request_id`, and explicit `admin_action`/`admin_denied` events.
- Structured JSON logs through `log_format = json`, reloadable with SIGHUP.
- Per-client destination ACLs (`client_allow`/`client_deny`),
  `client_isolation` and `strict_source` enforcement.
- Quota windows with daily, weekly, monthly or custom periods; drop or
  throttle actions; grace; persisted quota state; and append-only usage
  history.
- Liveness and readiness endpoints (`/healthz` and `/readyz`) and optional
  bearer-token protection for Prometheus metrics.
- Client configuration export, delegated `/64` allocation and client
  lifecycle controls (`--disable-client`, `--enable-client`,
  `--expire-client`).
- Zero-downtime key staging and promotion for one client or a fleet, with
  server-side key files, plus side-effect-free `--doctor` endpoint probing.
- Ordered relay failover and optional automatic failback to the preferred
  endpoint.

### Changed

- The control socket is `0600` for the owner by default and `0660` with
  `control_group`; role changes require a restart because the group and mode
  are set when the socket is bound.
- Direct CLI mutations and signal-based reloads now enforce the same role
  matrix as the control channel.
- Audit records carry actor attribution in addition to the existing event
  fields.
- The version is now `2.5.0`. The wire protocol remains version 5.

### Upgrade notes

- Existing configurations remain valid. Without any `control_*` setting the
  socket stays owner-only and existing installations keep their previous
  access model.
- Role-group members must also belong to `control_group`, because that group
  controls access to the socket itself.
- The service account is not implicitly elevated when `control_group` is
  configured. Add it to `control_admin_group` if it must administer its own
  instance.
- Changing any `control_*` setting requires a restart.
- The control channel is POSIX-only. Windows rejects `control_group`; the
  Windows client continues to use `--reload` and `--stats` locally.
- A direct `kill -HUP` is governed by normal POSIX process permissions, not
  by the control-channel role matrix.
- Audit writing remains best-effort; this release does not add tamper-evident
  or write-once storage.
- The remote mTLS/OIDC administration API and two-person approval workflow are
  not part of 2.5.0.

### Verification

- `make check`: 573 checks, 0 failures; control-channel tests pass.
- CI covers gcc, clang, ASan/UBSan, the network-namespace integration suite
  and Linux/Windows packaging.
