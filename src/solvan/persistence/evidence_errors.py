"""Closed evidence-tool persistence failures."""


class ToolAuthorizationError(RuntimeError):
    """The invocation, tool, resource, deadline, or budget is not authorized."""


class ToolCallBusy(RuntimeError):
    """An identical live tool call is already executing."""
