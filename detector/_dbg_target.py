import sys
data = sys.stdin.buffer.read()
if data.startswith(b'PWN'):
    raise IndexError('planted')
