"""Whether this deployment is connected to Google Cloud, decided once.

Two definitions of "connected" existed, and they disagreed about reads. The
approval path treated a locally connected development host as connected and
demanded a verified Google identity; the reader path tested only the deployed
authority mode, so the same host authenticated writes and quietly answered reads
as a fixture. A deployment reaching real customer telemetry was serving one of
them under nobody's identity.

Absence of the connected markers is what makes a harness hermetic, so this says
yes only when a marker is explicitly present. A missing or misspelled variable
yields a harness that reaches nothing, never a connected deployment that reaches
everything without an identity.
"""

from __future__ import annotations

import os

#: The reader identity of a hermetic harness: a local database, seeded fixtures,
#: and no path to customer or cloud-connected data. It is deliberately not
#: `user:`-shaped, because every human principal is, and an identity that can
#: never be a person should never be mistakable for one. It holds no role
#: binding — `actor_role_bindings` admits only `user:` principals — so it cannot
#: satisfy an operator, approver, or administrator check.
FIXTURE_READER_PRINCIPAL = "local-development-reader"


def connected_to_google_cloud() -> bool:
    """True when this process can reach Google Cloud under a real identity."""

    return (
        os.environ.get("SOLVAN_PLATFORM_AUTHORITY_MODE") == "GOOGLE_CLOUD_IAM"
        or os.environ.get("SOLVAN_LOCAL_CONNECTED_GCP") == "true"
    )


def is_fixture_principal(principal: str) -> bool:
    """True for the harness reader, which may never carry authority."""

    return principal == FIXTURE_READER_PRINCIPAL
