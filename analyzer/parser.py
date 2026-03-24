import re


def parse_input(input_type: str, content: str) -> str:
    """
    Takes raw input of any type and returns clean text
    ready for the detection engine.
    """

    if input_type == "text":
        return _parse_text(content)

    elif input_type == "log":
        return _parse_log(content)

    elif input_type == "sql":
        return _parse_sql(content)

    elif input_type == "chat":
        return _parse_chat(content)

    else:
        # Unknown type — just return as-is
        return content.strip()


def _parse_text(content: str) -> str:
    """
    Plain text — just clean up whitespace.
    """
    return content.strip()


def _parse_log(content: str) -> str:
    """
    Log files — strip timestamps and log levels
    to focus on the actual message content.
    Also keeps original for line number tracking.
    """
    cleaned_lines = []
    lines = content.splitlines()

    for line in lines:
        # Remove common timestamp formats
        # e.g. "2026-03-10 10:00:01 INFO " → ""
        line = re.sub(
            r"\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(\.\d+)?\s*",
            "",
            line
        )
        # Remove log level prefixes like INFO, DEBUG, WARNING, ERROR
        line = re.sub(
            r"^(INFO|DEBUG|WARNING|ERROR|CRITICAL|WARN)\s*",
            "",
            line,
            flags=re.IGNORECASE
        )
        cleaned_lines.append(line.strip())

    return "\n".join(cleaned_lines)


def _parse_sql(content: str) -> str:
    """
    SQL input — extract string values from queries
    where sensitive data is most likely to hide.
    """
    # Find all quoted string values in SQL
    values = re.findall(r"'([^']*)'", content)
    # Also keep the full content for pattern matching
    return content.strip() + "\n" + "\n".join(values)


def _parse_chat(content: str) -> str:
    """
    Chat input — remove speaker labels like
    "User: " or "Bot: " and return just the messages.
    """
    lines = content.splitlines()
    cleaned = []
    for line in lines:
        # Remove "Speaker: " prefix
        line = re.sub(r"^[\w\s]+:\s*", "", line)
        cleaned.append(line.strip())
    return "\n".join(cleaned)
