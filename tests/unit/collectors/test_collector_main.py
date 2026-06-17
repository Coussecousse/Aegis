"""Unit tests for the collector daemon's line-extraction resilience."""

from __future__ import annotations

from aegis.collectors.__main__ import _extract_complete_lines


def test_extract_returns_complete_lines_and_byte_count() -> None:
    data = b'{"a":1}\n{"b":2}\n'
    lines, consumed = _extract_complete_lines(data)
    assert lines == ['{"a":1}', '{"b":2}']
    assert consumed == len(data)


def test_extract_holds_back_partial_trailing_line() -> None:
    # Last record is mid-write (no trailing newline) → not consumed.
    data = b'{"a":1}\n{"b":2'
    lines, consumed = _extract_complete_lines(data)
    assert lines == ['{"a":1}']
    assert consumed == len(b'{"a":1}\n')


def test_extract_no_complete_line_consumes_nothing() -> None:
    lines, consumed = _extract_complete_lines(b'{"partial":')
    assert lines == []
    assert consumed == 0


def test_extract_skips_blank_lines() -> None:
    lines, consumed = _extract_complete_lines(b'{"a":1}\n\n  \n{"b":2}\n')
    assert lines == ['{"a":1}', '{"b":2}']


def test_record_split_across_two_polls_is_not_lost() -> None:
    # Poll 1 sees a complete record plus the start of a second.
    poll1 = b'{"a":1}\n{"b":'
    lines1, consumed1 = _extract_complete_lines(poll1)
    assert lines1 == ['{"a":1}']

    # Next poll starts after the consumed bytes; the rest of the record arrives.
    remainder = poll1[consumed1:] + b"2}\n"
    lines2, consumed2 = _extract_complete_lines(remainder)
    assert lines2 == ['{"b":2}']
    assert consumed2 == len(remainder)
