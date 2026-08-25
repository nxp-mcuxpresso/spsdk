#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for the SPSDK Verifier utility."""

from spsdk.utils.verifier import Verifier, VerifierResult


def test_has_warnings_empty() -> None:
    """An empty verifier has no warnings."""
    verifier = Verifier("Test")
    assert verifier.has_warnings is False


def test_has_warnings_only_success() -> None:
    """A verifier with only successful records has no warnings."""
    verifier = Verifier("Test")
    verifier.add_record("ok", VerifierResult.SUCCEEDED)
    assert verifier.has_warnings is False


def test_has_warnings_with_warning() -> None:
    """A verifier containing a warning record reports having warnings."""
    verifier = Verifier("Test")
    verifier.add_record("warn", VerifierResult.WARNING)
    assert verifier.has_warnings is True


def test_has_warnings_with_error_only() -> None:
    """An error record alone does not count as a warning."""
    verifier = Verifier("Test")
    verifier.add_record("err", VerifierResult.ERROR)
    assert verifier.has_warnings is False


def test_has_warnings_mixed_records() -> None:
    """A verifier with mixed records reports having warnings when any warning exists."""
    verifier = Verifier("Test")
    verifier.add_record("ok", VerifierResult.SUCCEEDED)
    verifier.add_record("err", VerifierResult.ERROR)
    verifier.add_record("warn", VerifierResult.WARNING)
    assert verifier.has_warnings is True


def test_has_warnings_nested_child() -> None:
    """A warning in a nested child verifier is detected by the parent."""
    parent = Verifier("Parent")
    child = Verifier("Child")
    child.add_record("warn", VerifierResult.WARNING)
    parent.add_child(child)
    assert parent.has_warnings is True


def test_has_warnings_nested_child_no_warning() -> None:
    """A parent has no warnings when neither it nor its children have warnings."""
    parent = Verifier("Parent")
    parent.add_record("ok", VerifierResult.SUCCEEDED)
    child = Verifier("Child")
    child.add_record("ok", VerifierResult.SUCCEEDED)
    parent.add_child(child)
    assert parent.has_warnings is False
