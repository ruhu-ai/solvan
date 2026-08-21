"""Cloud SQL authority for immutable Operational Guidance revisions."""

from solvan.persistence.operational_guidance_annotations import OperationalGuidanceAnnotationsMixin
from solvan.persistence.operational_guidance_authoring import OperationalGuidanceAuthoringMixin
from solvan.persistence.operational_guidance_lifecycle import OperationalGuidanceLifecycleMixin
from solvan.persistence.operational_guidance_projection import OperationalGuidanceProjectionMixin
from solvan.persistence.operational_guidance_runtime import OperationalGuidanceRuntimeMixin
from solvan.persistence.operational_guidance_types import (
    GuidanceLifecycleCommit,
    GuidanceSelectedMaterial,
    GuidanceStepVerdict,
)

__all__ = [
    "GuidanceLifecycleCommit",
    "GuidanceSelectedMaterial",
    "GuidanceStepVerdict",
    "PostgresOperationalGuidanceStore",
]


class PostgresOperationalGuidanceStore(
    OperationalGuidanceAuthoringMixin,
    OperationalGuidanceAnnotationsMixin,
    OperationalGuidanceLifecycleMixin,
    OperationalGuidanceRuntimeMixin,
    OperationalGuidanceProjectionMixin,
):
    """Cohesive facade over one caller-owned PostgreSQL transaction."""
