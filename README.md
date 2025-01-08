[![CharmHub Badge](https://charmhub.io/smtp-relay/badge.svg)](https://charmhub.io/smtp-relay)
[![Publish to edge](https://github.com/canonical/smtp-relay-operator/actions/workflows/publish_charm.yaml/badge.svg)](https://github.com/canonical/smtp-relay-operator/actions/workflows/publish_charm.yaml)
[![Promote charm](https://github.com/canonical/smtp-relay-operator/actions/workflows/promote_charm.yaml/badge.svg)](https://github.com/canonical/smtp-relay-operator/actions/workflows/promote_charm.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

# SMTP Relay Operator

A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators)
deploying and managing a postfix SMTP relay server on bare metal. SMTP
is an Internet standard communication protocol for email transmission.

Like any Juju charm, this charm supports one-line deployment, configuration, integration, scaling, and more. For Charmed smtp-relay, this includes:
  - Scaling
  - Integration with SSO
  - Integration with S3 for redundant file storage

For information about how to deploy, integrate, and manage this charm, see the Official [smtp-relay Operator Documentation](https://charmhub.io/smtp-relay/docs).


## Get started

You can follow the tutorial [here](https://charmhub.io/smtp-relay/docs/getting-started).

### Basic operations

The following actions are available for this charm:
    - refresh-external-resources: refresh the external resources (e.g. S3 bucket)
    - add-admmin: add an admin user
    - anonymize-user: anonymize a user

You can check out the [full list of actions here](https://charmhub.io/smtp-relay/actions).

## Integrations

This charm can be integrated with other Juju charms and services:

    - [Redis](https://charmhub.io/redis-k8s): Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache and message broker.
    - [S3](https://charmhub.io/s3-integrator): Amazon Simple Storage Service (Amazon S3) is an object storage service that provides secure, durable, highly available storage with massive scalability and low latency.
    - [Postgresql](https://charmhub.io/postgresql-k8s): PostgreSQL is a powerful, open source object-relational database system. It has more than 15 years of active development and a proven architecture that has earned it a strong reputation for reliability, data integrity, and correctness.

    and much more. You can find the full list of integrations [here](https://charmhub.io/smtp-relay/integrations).

## Learn more
* [Read more](https://charmhub.io/smtp-relay) <!--Link to the charm's official documentation-->
* [Developer documentation](https://www.postfix.org/documentation.html) <!--Link to any developer documentation-->
* [Official webpage](https://www.postfix.org/) <!--(Optional) Link to official webpage/blog/marketing content-->
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--(Optional) Link to a page or section about troubleshooting/FAQ-->
## Project and community
* [Issues](https://github.com/canonical/smtp-relay-operator/issues) <!--Link to GitHub issues (if applicable)-->
* [Contributing](https://charmhub.io/smtp-relay/docs/how-to-contribute) <!--Link to any contribution guides-->
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com) <!--Link to contact info (if applicable), e.g. Matrix channel-->

