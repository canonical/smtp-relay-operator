# Charm architecture

The SMTP Relay charm deploys a Postfix server configured as instructed by the configuration options.

The SMTP Relay can be deployed in Kubernetes and machine models, but in order to protect the server reputation, it is recommended to deploy it in machine models.
As a workloadless charm, the SMTP Relay doesn't have any OCI images.
