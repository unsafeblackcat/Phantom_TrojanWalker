"""
Pytest configuration and fixtures for Phantom TrojanWalker tests.
"""
import os
import sys
import pytest

# Add project root to path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Check for Ghidra availability
def ghidra_available():
    """Check if Ghidra/pyghidra is available."""
    ghidra_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if not ghidra_dir or not os.path.isdir(ghidra_dir):
        return False
    try:
        import pyghidra
        return True
    except ImportError:
        return False

# Pytest marker for tests requiring Ghidra
requires_ghidra = pytest.mark.skipif(
    not ghidra_available(),
    reason="Ghidra/pyghidra not available (set GHIDRA_INSTALL_DIR and install pyghidra)"
)
