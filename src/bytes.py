def has_hex_prefix(hex_string: str) -> bool:
    return hex_string.startswith("0x")


def remove_hex_prefix(hex_string: str) -> str:
    if has_hex_prefix(hex_string):
        return hex_string[len("0x"):]

    return hex_string


def to_hex(b: bytes) -> str:
    return b.hex()


def hex_to_bytes(hex_string: str) -> bytes:
    return bytes.fromhex(remove_hex_prefix(hex_string))


def compare_bytes(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return a[i] - b[i]

    return len(a) - len(b)


def equals_bytes(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def concat_bytes(a: bytes, b: bytes) -> bytes:
    return a+b
