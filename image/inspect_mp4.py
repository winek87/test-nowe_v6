import sys, struct

def walk(data, offset=0, end=None, depth=0):
    if end is None: end = len(data)
    while offset + 8 <= end:
        size = struct.unpack(">I", data[offset:offset+4])[0]
        btype = data[offset+4:offset+8].decode("ascii", "replace")
        hdr = 8
        if size == 1:
            if offset + 16 > end: break
            size = struct.unpack(">Q", data[offset+8:offset+16])[0]
            hdr = 16
        elif size == 0:
            size = end - offset
        print(f"{'  '*depth}{btype:6s} offset={offset:8d} size={size:8d}")
        # Kontenery, w które warto wejść
        if btype in ("moov", "trak", "mdia", "minf", "stbl", "udta"):
            walk(data, offset+hdr, min(offset+size, end), depth+1)
        if size <= 0: break
        offset += size

data = open(sys.argv[1], "rb").read()
print(f"Plik: {len(data)} bajtow\n")
walk(data)
