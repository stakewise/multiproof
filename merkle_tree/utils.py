from typing import Any, List


def check_bounds(array: List[Any], index: int) -> None:
    if index < 0 or index >= len(array):
        raise ValueError("Index out of bounds")
