from typing import Any, TypedDict

import reflex as rx
from reflex.event import passthrough_event_spec


class WindowMessage(TypedDict):
    """Message type from the message listener."""

    origin: str
    data: Any
    timestamp: float


class MessageListener(rx.Component):
    """Message listener component."""

    library = "$/public" + rx.asset("messageListener.js", shared=True)

    tag = "MessageListener"

    allowed_origin: str | None = None
    on_message: rx.EventHandler[passthrough_event_spec(WindowMessage)]


message_listener = MessageListener.create
