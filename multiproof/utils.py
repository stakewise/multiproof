def check_bounds(array: list, index: int) -> None:
    if index < 0 or index >= len(array):
        raise ValueError("Index out of bounds")
