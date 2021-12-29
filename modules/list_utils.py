from __future__ import annotations
from typing import Generator

# Utility functions for manipulating lists
def flatten(list_of_lists: iter[iter]) -> list:
    """Flattens a list_of_lists."""
    return [item for sublist in list_of_lists for item in sublist]