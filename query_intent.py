"""Deterministic routing and the complete grammar for sample sales totals."""
from __future__ import annotations

import re
from typing import Literal


class InsufficientEvidence(ValueError):
    """The requested operation cannot be answered from the supported data."""


_DOCUMENT = re.compile(r"\b(?:reports?|pdfs?|documents?|polic(?:y|ies)|handbooks?)\b")
_EMPLOYEES = re.compile(r"\b(?:employees?|staff directory)\b")
_LOGS = re.compile(r"\b(?:logs?|alerts?|errors?|warn|warnings?)\b")
_SALES = re.compile(r"\b(?:sales?|transactions?|revenues?|amounts?)\b")
LOG_LEVEL_ALIASES = {
    "error": "ERROR", "errors": "ERROR",
    "warn": "WARN", "warning": "WARN", "warnings": "WARN",
    "info": "INFO", "informational": "INFO",
}
LOG_QUERY_WORDS = frozenset({
    "a", "and", "are", "can", "entries", "entry", "for", "latest", "list", "log",
    "logs", "match", "matching", "me", "most", "or", "please", "recent", "records",
    "show", "the", "what", "you",
})
_REGIONS = {
    "emea": "EMEA", "apac": "APAC", "na": "NA",
    "north america": "NA", "asia pacific": "APAC",
}
_REGION = "|".join(_REGIONS)
_METRIC = r"(?:sales|revenue|sales revenue)"
_SCOPE = rf"(?:(?P<suffix>{_REGION})(?: region)?|all regions|worldwide|globally)"
_TOTAL = re.compile(
    rf"(?:(?:what (?:is|are)|how much is|show(?: me)?|give me) )?(?:the )?"
    rf"(?:(?:total )?(?P<prefix>{_REGION}) {_METRIC}"
    rf"|(?:total )?{_METRIC}(?: (?:(?:in|for|from|across) (?:the )?)?{_SCOPE})?)"
)
_DIRECTORY = re.compile(
    r"(?:(?:list|show(?: me)?|give me|what are) )?(?:the )?"
    r"(?:employees?|staff directory|employee directory|employee names"
    r"|employee names and departments)"
)


def _normalise(query: str) -> str:
    return " ".join(query.casefold().split()).rstrip("?.!").rstrip()


def route(query: str) -> Literal["document", "employees", "logs", "sales"]:
    value = _normalise(query)
    if _DOCUMENT.search(value):
        return "document"
    structured = [
        name for name, pattern in (
            ("employees", _EMPLOYEES), ("logs", _LOGS), ("sales", _SALES)
        ) if pattern.search(value)
    ]
    if len(structured) > 1:
        raise InsufficientEvidence("Specify one structured source per question.")
    if _EMPLOYEES.search(value):
        return "employees"
    if _LOGS.search(value):
        return "logs"
    if _SALES.search(value):
        return "sales"
    return "document"


def sales_region(query: str) -> str | None:
    # Accept the entire supported request. No unmatched words, punctuation in
    # the middle, or constraints may be dropped before issuing a calculation.
    value = _normalise(query)
    match = _TOTAL.fullmatch(value)
    if not match:
        raise InsufficientEvidence("Only an overall total or a total for one supported region is available.")
    return _REGIONS.get(match["prefix"] or match["suffix"])


def require_directory_list(query: str) -> None:
    if not _DIRECTORY.fullmatch(_normalise(query)):
        raise InsufficientEvidence("Only a list of directory names and departments is available.")
