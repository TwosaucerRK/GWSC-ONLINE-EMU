"""Response serialization.

The service answers XML through ``.asmx`` endpoints. The root node is
``<Response>`` and collections are emitted as
``<Tag Count="n"><Item>...</Item>...</Tag>`` so a client can walk them with
XPath like ``//Response/RockstarAccount``.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

HEADER = '<?xml version="1.0" encoding="utf-8"?>'


def _scalar(tag: str, value) -> str:
    return "<%s>%s</%s>" % (tag, escape(str(value)), tag)


def render(fields) -> bytes:
    out = [HEADER, "<Response>"]
    for key, value in fields.items():
        if isinstance(value, (list, tuple)):
            out.append('<%s Count="%d">' % (key, len(value)))
            for item in value:
                out.append("<Item>")
                for item_key, item_value in item.items():
                    out.append(_scalar(item_key, item_value))
                out.append("</Item>")
            out.append("</%s>" % key)
        elif isinstance(value, dict):
            out.append("<%s>" % key)
            for inner_key, inner_value in value.items():
                out.append(_scalar(inner_key, inner_value))
            out.append("</%s>" % key)
        else:
            out.append(_scalar(key, value))
    out.append("</Response>")
    return ("\n".join(out) + "\n").encode("utf-8")
