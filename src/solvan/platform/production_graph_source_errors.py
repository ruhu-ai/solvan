"""Closed provider-failure taxonomy shared by Production Graph adapters."""


class GraphSourceUnavailable(RuntimeError):
    """A source could not establish a conclusive observation."""


class GraphSourceDenied(GraphSourceUnavailable):
    """The provider explicitly refused the read."""


class GraphSourceNotEntitled(GraphSourceUnavailable):
    """The customer does not hold the separately required entitlement."""
