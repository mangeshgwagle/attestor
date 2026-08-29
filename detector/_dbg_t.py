def run(data):
    if len(data) < 6:
        return None
    if data[0:3] != b"PWN":
        return None
    if data[5:6] != b"\x00":
        return None
    table = [1, 2]
    return table[data[4]]
