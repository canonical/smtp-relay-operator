# SMTP relay operator

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

## In this documentation

| | |
|--|--|
| [How-to guides](https://charmhub.io/smtp-relay/docs/how-to-contribute) </br> Step-by-step guides covering key operations and common tasks | 
| [Reference](https://charmhub.io/smtp-relay/docs/reference-actions) </br> Technical information - specifications, APIs, architecture | 

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as the code. As such, we welcome community contributions, suggestions and constructive feedback on our documentation. Our documentation is hosted on the [Charmhub forum](https://discourse.charmhub.io/t/smtp-relay-documentation-overview/16137) to enable easy collaboration. Please use the "Help us improve this documentation" links on each documentation page to either directly change something you see that's wrong, ask a question, or make a suggestion about a potential change via the comments section.

If there's a particular area of documentation that you'd like to see that's missing, please [file a bug](https://github.com/canonical/smtp-relay-operator/issues).

## Project and community

The SMTP Relay Operator is a member of the Ubuntu family. It's an open-source project that warmly welcomes community projects, contributions, suggestions, fixes, and constructive feedback.

- [Code of conduct](https://ubuntu.com/community/code-of-conduct)
- [Get support](https://discourse.charmhub.io/)
- [Join our online chat](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
- [Contribute](https://github.com/canonical/smtp-relay-operator/blob/main/CONTRIBUTING.md)

Thinking about using the SMTP Relay Operator for your next project? [Get in touch](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)!

# Contents 

1. [How-to](how-to)
   1. [Contribute](how-to/contribute.md)
1. [Reference](reference)
  1. [Actions](reference/actions.md)
  1. [External access](reference/external_access.md)