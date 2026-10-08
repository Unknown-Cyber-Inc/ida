class _Seg:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end


_segs = [_Seg(0x401000, 0x401100), _Seg(0x402000, 0x402080)]


def get_first_seg():
    return _segs[0]


def get_next_seg(ea):
    for i, s in enumerate(_segs):
        if s.start_ea == ea and i + 1 < len(_segs):
            return _segs[i + 1]
    return None
