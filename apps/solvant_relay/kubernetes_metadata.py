"""Closed Kubernetes metadata adapter for a policy-bound namespace and kind.

The Relay constructs the Kubernetes API path itself.  A job contains neither a
cluster address, arbitrary API path, label selector, credential nor request
method.  The policy pins the customer API host, while the customer workload's
own identity is the only identity used for the call.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from apps.solvant_relay.runtime import RelayRuntimeError
from solvan.platform.google_rest import GoogleRestSession

_RESOURCE_PATHS = {
    "Deployment": ("/apis/apps/v1", "deployments"),
    "StatefulSet": ("/apis/apps/v1", "statefulsets"),
    "DaemonSet": ("/apis/apps/v1", "daemonsets"),
    "Pod": ("/api/v1", "pods"),
    "Service": ("/api/v1", "services"),
}
_NAMESPACE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_SERVICE_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class KubernetesMetadataRelayAdapter:
    """Read only metadata from one customer-approved Kubernetes namespace."""

    def __init__(self, *, session: GoogleRestSession) -> None:
        self._session = session

    def read(
        self,
        *,
        adapter: Mapping[str, Any],
        parameters: Mapping[str, Any],
        maximum_pages: int,
        maximum_items: int,
        maximum_bytes: int,
        maximum_calls: int,
    ) -> tuple[Mapping[str, Any], ...]:
        del maximum_pages, maximum_bytes
        required = {
            "resource_binding_id",
            "namespace",
            "resource_kind",
            "service_key",
            "maximum_items",
        }
        if set(parameters) != required or maximum_calls < 1:
            raise RelayRuntimeError("Kubernetes metadata request is not closed")
        namespace = parameters["namespace"]
        resource_kind = parameters["resource_kind"]
        service_key = parameters["service_key"]
        limit = parameters["maximum_items"]
        if (
            not isinstance(namespace, str)
            or _NAMESPACE.fullmatch(namespace) is None
            or namespace not in adapter.get("allowed_namespaces", [])
            or not isinstance(resource_kind, str)
            or resource_kind not in _RESOURCE_PATHS
            or resource_kind not in adapter.get("allowed_resource_kinds", [])
            or not isinstance(service_key, str)
            or _SERVICE_KEY.fullmatch(service_key) is None
            or not isinstance(limit, int)
            or not 1 <= limit <= min(200, maximum_items)
        ):
            raise RelayRuntimeError("Kubernetes metadata parameters are not locally authorized")
        endpoint = adapter.get("endpoint")
        if not isinstance(endpoint, Mapping):
            raise RelayRuntimeError("Kubernetes metadata endpoint is malformed")
        host = endpoint.get("host")
        if not isinstance(host, str) or not host:
            raise RelayRuntimeError("Kubernetes metadata endpoint is not locally authorized")
        api_root, plural = _RESOURCE_PATHS[resource_kind]
        response = self._session.get(
            "https://"
            + host
            + api_root
            + "/namespaces/"
            + quote(namespace, safe="")
            + "/"
            + plural,
            params={"labelSelector": f"app.kubernetes.io/name={service_key}", "limit": limit},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise RelayRuntimeError("Kubernetes metadata response is malformed")
        items = payload.get("items")
        if not isinstance(items, list):
            raise RelayRuntimeError("Kubernetes metadata response is malformed")
        records: list[Mapping[str, Any]] = []
        for item in items[:limit]:
            if not isinstance(item, Mapping):
                raise RelayRuntimeError("Kubernetes metadata item is malformed")
            metadata = item.get("metadata")
            if not isinstance(metadata, Mapping):
                raise RelayRuntimeError("Kubernetes metadata item is malformed")
            name = metadata.get("name")
            item_namespace = metadata.get("namespace")
            uid = metadata.get("uid")
            labels = metadata.get("labels", {})
            if (
                not isinstance(name, str)
                or not isinstance(item_namespace, str)
                or item_namespace != namespace
                or not isinstance(uid, str)
                or not isinstance(labels, Mapping)
                or labels.get("app.kubernetes.io/name") != service_key
            ):
                raise RelayRuntimeError("Kubernetes metadata item is outside the closed selector")
            records.append(
                {
                    "kind": "KUBERNETES_METADATA",
                    "resource_kind": resource_kind,
                    "namespace": namespace,
                    "name": name,
                    "uid": uid,
                    "labels": {
                        "app.kubernetes.io/name": service_key,
                        **(
                            {"app.kubernetes.io/version": labels["app.kubernetes.io/version"]}
                            if isinstance(labels.get("app.kubernetes.io/version"), str)
                            else {}
                        ),
                    },
                }
            )
        return tuple(records)
