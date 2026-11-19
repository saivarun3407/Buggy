"""Real bounty programs: official scope import and the rules that bind an engagement to it.

An engagement becomes a *program engagement* when the operator imports a
program's official scope (``buggy-cli scope import``). That writes two files
under the operator-controlled root:

``roe.json``      the enforced scope, always in ``enforce`` mode
``program.json``  where the scope came from, the program's rate limit and its
                  banned techniques

While ``program.json`` exists the engagement runs under the stricter rules in
:mod:`buggy.program.gate`: enforce mode only, operator approval before any
state-changing request and before any report is released, and no finding
without a captured in-scope request and a remediation.
"""

from __future__ import annotations

from buggy.program.record import (
    BASELINE_BANNED_TECHNIQUES,
    PROGRAM_FILE,
    load_program,
)

__all__ = ["BASELINE_BANNED_TECHNIQUES", "PROGRAM_FILE", "load_program"]
