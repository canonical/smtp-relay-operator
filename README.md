[![CharmHub Badge](https://charmhub.io/smtp-relay/badge.svg)](https://charmhub.io/smtp-relay)
[![Publish to edge](https://github.com/canonical/smtp-relay-operator/actions/workflows/publish_charm.yaml/badge.svg)](https://github.com/canonical/smtp-relay-operator/actions/workflows/publish_charm.yaml)
[![Promote charm](https://github.com/canonical/smtp-relay-operator/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/smtp-relay-operator/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

# SMTP Relay Operator

A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators)
deploying and managing a postfix SMTP relay server on bare metal. SMTP
is an Internet standard communication protocol for email transmission.

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

For information about how to deploy, integrate, and manage this charm, see the Official [smtp-relay Operator Documentation](https://charmhub.io/smtp-relay/docs).


## Get started

You can follow the tutorial [here](https://charmhub.io/smtp-relay/docs/getting-started).


## Learn more
* [Read more](https://charmhub.io/smtp-relay) <!--Link to the charm's official documentation-->
* [Developer documentation](https://www.postfix.org/documentation.html) <!--Link to any developer documentation-->
* [Official webpage](https://www.postfix.org/) <!--(Optional) Link to official webpage/blog/marketing content-->
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--(Optional) Link to a page or section about troubleshooting/FAQ-->
## Project and community
* [Issues](https://github.com/canonical/smtp-relay-operator/issues) <!--Link to GitHub issues (if applicable)-->
* [Contributing](https://charmhub.io/smtp-relay/docs/how-to-contribute) <!--Link to any contribution guides-->
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--Link to contact info (if applicable), e.g. Matrix channel-->

