# SMTP Relay Charm

## Description

The SMTP Relay Charm installs a versatile postfix SMTP relay server.

It's intended to be highly configurable, setting up Postfix as requested.

Features include (not limited to):
- set up base Postfix system
- relay through another MTA
- set up virtual aliases and transport maps
- restrict relaying per domain, sender, recipient, headers checks
- enable SPF subsystem
- set up authenticated submission service
- restrict sender address per user
- fine-tune TLS settings
- set up limits (rate, size, connections, ...)
- set up Nagios monitoring
- set up rsyslog relaying and log retention

## Usage

Provision a Juju environment then deploy 2 units with:

```
juju deploy -n2 smtp-relay
```

### Scale Out Usage

To horizontally scale, adding more read-only standbys:

```
juju add-unit smtp-relay
```

---

## Testing

Just run `make unittest`.

---

For more details, [see here](https://charmhub.io/smtp-relay/configure).
