"""Backward-compatibility shim.

The PolicyEngine implementation has moved to securegate.policy.engine.
This module re-exports it so existing ``from securegate.policy import
PolicyEngine`` imports continue to work.
"""

from .policy.engine import PolicyEngine  # noqa: F401


__all__ = ["PolicyEngine"]
