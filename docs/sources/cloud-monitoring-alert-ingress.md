# Cloud Monitoring alert ingress source record

Status: design-source record for target Alert Triage; not a runtime receipt or
implementation claim.

Retrieved: 2026-08-13

## Authoritative sources

- [Cloud Monitoring notification options](https://docs.cloud.google.com/monitoring/support/notification-options)
  documents the notification payload's incident lifecycle and Pub/Sub delivery
  option.
- [Pub/Sub push subscriptions](https://docs.cloud.google.com/pubsub/docs/push)
  documents the push envelope and acknowledgement/retry behavior.
- [Authenticate push subscriptions](https://docs.cloud.google.com/pubsub/docs/authenticate-push-subscriptions)
  documents audience-bound OIDC authentication for push delivery.
- [Pub/Sub exactly-once delivery](https://docs.cloud.google.com/pubsub/docs/exactly-once-delivery)
  records the limitation that push subscriptions do not support exactly-once
  delivery.
- [Pub/Sub message ordering](https://docs.cloud.google.com/pubsub/docs/ordering)
  records that ordering is not available without both ordering-key publication
  and compatible subscription configuration.

## Provider-observed fields and behavior

The wrapped Pub/Sub push envelope supplies `message.messageId`, publish data,
and `subscription`; it does **not** supply a topic field. A successful HTTP
response is Pub/Sub's acknowledgement signal, but the application receives no
later broker-acknowledgement receipt; a lost response can cause redelivery.
Cloud Monitoring's notification payload supplies the provider incident lifecycle
fields used by specification 21's v1.2 transition normalization, including the
metrics-scope `incident.scoping_project_id` and separately attributed monitored
resource labels. The project identities can legitimately differ.

## Solvan target design decisions

Cloud Monitoring's provider incident lifecycle and Pub/Sub transport delivery
are different identities. Specification 21 records each authenticated push
receipt separately from its normalized provider lifecycle event, commits the
semantic outcome before selecting an HTTP success response, and treats
redelivery as normal. The initial slice binds one exact Cloud Monitoring
project/topic/subscription/push service account/audience to one connection
revision. The runtime verifies `subscription` from the envelope and verifies the
topic-to-subscription relation from that frozen connection
capability/configuration receipt; it does not claim the envelope proves a topic
or broker acknowledgement. This design authorizes neither a generic webhook,
process-wide project fallback, nor provider-driven scope selection. The
connection receipt binds the scoping project; the monitored-resource project is
separately checked against the Graph/environment/coverage contracts. Arrival
order is never treated as provider lifecycle order.
