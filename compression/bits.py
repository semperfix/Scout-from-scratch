"""Bit-level I/O for the compression stack. All DEFLATE bit orderings are
LSB-first within each byte (RFC 1951); Huffman codes are MSB-first logically
but packed into the stream LSB-first. This module handles both."""

class BitWriter:
    def __init__(self):
        self.buf = bytearray()
        self.acc = 0      # accumulator
        self.nbits = 0    # bits currently in accumulator

    def write_bits(self, value, n):
        """Write n bits of value, LSB first (DEFLATE packing order)."""
        assert 0 <= value < (1 << n), (value, n)
        self.acc |= (value << self.nbits)
        self.nbits += n
        while self.nbits >= 8:
            self.buf.append(self.acc & 0xFF)
            self.acc >>= 8
            self.nbits -= 8

    def write_bits_msb(self, value, n):
        """Write n bits MSB first (used for Huffman code emission, where the
        canonical code is defined MSB-first but stored LSB-reversed)."""
        for i in range(n - 1, -1, -1):
            self.write_bits((value >> i) & 1, 1)

    def align(self):
        """Pad with zeros to the next byte boundary."""
        if self.nbits:
            self.buf.append(self.acc & 0xFF)
            self.acc = 0
            self.nbits = 0

    def bytes(self):
        self.align()
        return bytes(self.buf)


class BitReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0      # byte position
        self.acc = 0
        self.nbits = 0

    def _fill(self):
        if self.pos < len(self.data):
            self.acc |= (self.data[self.pos] << self.nbits)
            self.pos += 1
            self.nbits += 8

    def read_bits(self, n):
        """Read n bits LSB first. Raises EOFError on truncation."""
        while self.nbits < n:
            if self.pos >= len(self.data):
                raise EOFError("truncated bit stream")
            self._fill()
        val = self.acc & ((1 << n) - 1)
        self.acc >>= n
        self.nbits -= n
        return val

    def read_bit(self):
        return self.read_bits(1)

    def align(self):
        self.acc = 0
        self.nbits = 0

    def read_bytes(self, n):
        self.align()
        if self.pos + n > len(self.data):
            raise EOFError("truncated byte stream")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return bytes(out)

    def eof(self):
        return self.pos >= len(self.data) and self.nbits == 0
