def get_full_flags(ea):
    return 0x100 | (ea & 0xFF)


def get_bytes_and_mask(ea, size):
    data = bytes((ea + i) & 0xFF for i in range(size))
    mask = b"\xff" * ((size + 7) // 8)
    return data, mask
