class _Func:
    def __init__(self, start):
        self.start_ea = start
        self.end_ea = start + 0x40


def get_func(ea):
    if 0x401000 <= ea < 0x402000:
        return _Func(ea & ~0x3F)
    return None
