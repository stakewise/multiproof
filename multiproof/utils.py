from typing import Optional

from eth_typing import HexStr, Primitives
from eth_utils import keccak as eth_utils_keccak
from eth_utils import to_bytes


def check_bounds(array: list, index: int) -> None:
    if index < 0 or index >= len(array):
        raise ValueError("Index out of bounds")


def keccak(
    primitive: Optional[Primitives] = None,
    text: Optional[str] = None,
    hexstr: Optional[HexStr] = None,
) -> bytes:
    """ Taken from web3py """
    if isinstance(primitive, (bytes, int, type(None))):
        input_bytes = to_bytes(primitive, hexstr=hexstr, text=text)
        return eth_utils_keccak(input_bytes)

    raise TypeError(
        f"You called keccak with first arg {primitive!r} and keywords "
        f"{{'text': {text!r}, 'hexstr': {hexstr!r}}}. You must call it with "
        "one of these approaches: keccak(text='txt'), keccak(hexstr='0x747874'), "
        "keccak(b'\\x74\\x78\\x74'), or keccak(0x747874)."
    )
