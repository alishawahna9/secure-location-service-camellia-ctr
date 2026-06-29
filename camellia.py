# ==========================================
#        Camellia Cipher - CTR Mode
#        Implements Camellia-128 per RFC 3713
# ==========================================

_SBOX1 = [
        112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
         35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
        134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
        166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
        139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
        223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
         20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
        254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
        170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
        16,  196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
        135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
         82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
        233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
        120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
        114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
         64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
    ]

_SBOX2 = [((s << 1) & 0xFF) | (s >> 7) for s in _SBOX1]
_SBOX3 = [((s >> 1)) | ((s << 7) & 0xFF) for s in _SBOX1]
_SBOX4 = [_SBOX1[((x << 1) & 0xFF) | (x >> 7)] for x in range(256)]


class Camellia:
    SBOX1 = _SBOX1
    SBOX2 = _SBOX2
    SBOX3 = _SBOX3
    SBOX4 = _SBOX4

    # Sigma constants for key schedule
    SIGMA = [
        0xA09E667F3BCC908B,
        0xB67AE8584CAA73B2,
        0xC6EF372FE94F82BE,
        0x54FF53A5F1D36F1C,
        0x10E527FADE682D1D,
        0xB05688C2B3E6C1FD,
    ]

    MASK64  = 0xFFFFFFFFFFFFFFFF
    MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 16:
            raise ValueError("Only 128-bit keys (16 bytes) are supported.")
        self.key = int.from_bytes(key_bytes, byteorder='big')
        self.subkeys = {}
        self._generate_subkeys()

    @staticmethod
    def _rotl128(x: int, shift: int) -> int:
        return ((x << shift) | (x >> (128 - shift))) & Camellia.MASK128

    def _f_func(self, f_in: int, ke: int) -> int:
        x = (f_in ^ ke) & self.MASK64
        t1 = (x >> 56) & 0xFF
        t2 = (x >> 48) & 0xFF
        t3 = (x >> 40) & 0xFF
        t4 = (x >> 32) & 0xFF
        t5 = (x >> 24) & 0xFF
        t6 = (x >> 16) & 0xFF
        t7 = (x >> 8) & 0xFF
        t8 = x & 0xFF

        t1 = self.SBOX1[t1]
        t2 = self.SBOX2[t2]
        t3 = self.SBOX3[t3]
        t4 = self.SBOX4[t4]
        t5 = self.SBOX2[t5]
        t6 = self.SBOX3[t6]
        t7 = self.SBOX4[t7]
        t8 = self.SBOX1[t8]

        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7

        return (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | \
               (y5 << 24) | (y6 << 16) | (y7 << 8) | y8

    @staticmethod
    def _fl_func(fl_in: int, kl: int) -> int:
        x1 = (fl_in >> 32) & 0xFFFFFFFF
        x2 = fl_in & 0xFFFFFFFF
        k1 = (kl >> 32) & 0xFFFFFFFF
        k2 = kl & 0xFFFFFFFF
        t = x1 & k1
        x2 ^= ((t << 1) & 0xFFFFFFFF) | (t >> 31)
        x1 ^= (x2 | k2)
        return ((x1 << 32) | x2) & Camellia.MASK64

    @staticmethod
    def _fl_inv_func(fl_in: int, kl: int) -> int:
        y1 = (fl_in >> 32) & 0xFFFFFFFF
        y2 = fl_in & 0xFFFFFFFF
        k1 = (kl >> 32) & 0xFFFFFFFF
        k2 = kl & 0xFFFFFFFF
        y1 ^= (y2 | k2)
        t = y1 & k1
        y2 ^= ((t << 1) & 0xFFFFFFFF) | (t >> 31)
        return ((y1 << 32) | y2) & Camellia.MASK64

    def _generate_subkeys(self):
        KL = self.key
        # KA generation
        D1 = (KL >> 64) & self.MASK64
        D2 = KL & self.MASK64
        D2 ^= self._f_func(D1, self.SIGMA[0])
        D1 ^= self._f_func(D2, self.SIGMA[1])
        D1 ^= (KL >> 64) & self.MASK64
        D2 ^= KL & self.MASK64
        D2 ^= self._f_func(D1, self.SIGMA[2])
        D1 ^= self._f_func(D2, self.SIGMA[3])
        KA = ((D1 << 64) | D2) & self.MASK128

        def hi(v): return (v >> 64) & self.MASK64
        def lo(v): return v & self.MASK64

        sk = self.subkeys
        sk['kw1'] = hi(KL)
        sk['kw2'] = lo(KL)
        sk['k1']  = hi(KA)
        sk['k2']  = lo(KA)
        sk['k3']  = hi(self._rotl128(KL, 15))
        sk['k4']  = lo(self._rotl128(KL, 15))
        sk['k5']  = hi(self._rotl128(KA, 15))
        sk['k6']  = lo(self._rotl128(KA, 15))
        sk['ke1'] = hi(self._rotl128(KA, 30))
        sk['ke2'] = lo(self._rotl128(KA, 30))
        sk['k7']  = hi(self._rotl128(KL, 45))
        sk['k8']  = lo(self._rotl128(KL, 45))
        sk['k9']  = hi(self._rotl128(KA, 45))
        sk['k10'] = lo(self._rotl128(KL, 60))
        sk['k11'] = hi(self._rotl128(KA, 60))
        sk['k12'] = lo(self._rotl128(KA, 60))
        sk['ke3'] = hi(self._rotl128(KL, 77))
        sk['ke4'] = lo(self._rotl128(KL, 77))
        sk['k13'] = hi(self._rotl128(KL, 94))
        sk['k14'] = lo(self._rotl128(KL, 94))
        sk['k15'] = hi(self._rotl128(KA, 94))
        sk['k16'] = lo(self._rotl128(KA, 94))
        sk['k17'] = hi(self._rotl128(KL, 111))
        sk['k18'] = lo(self._rotl128(KL, 111))
        sk['kw3'] = hi(self._rotl128(KA, 111))
        sk['kw4'] = lo(self._rotl128(KA, 111))

    def encrypt_block(self, block: bytes) -> bytes:
        D1 = int.from_bytes(block[0:8], byteorder='big')
        D2 = int.from_bytes(block[8:16], byteorder='big')
        sk = self.subkeys

        D1 ^= sk['kw1']
        D2 ^= sk['kw2']

        D2 ^= self._f_func(D1, sk['k1']);  D1 ^= self._f_func(D2, sk['k2'])
        D2 ^= self._f_func(D1, sk['k3']);  D1 ^= self._f_func(D2, sk['k4'])
        D2 ^= self._f_func(D1, sk['k5']);  D1 ^= self._f_func(D2, sk['k6'])

        D1 = self._fl_func(D1, sk['ke1'])
        D2 = self._fl_inv_func(D2, sk['ke2'])

        D2 ^= self._f_func(D1, sk['k7']);  D1 ^= self._f_func(D2, sk['k8'])
        D2 ^= self._f_func(D1, sk['k9']);  D1 ^= self._f_func(D2, sk['k10'])
        D2 ^= self._f_func(D1, sk['k11']); D1 ^= self._f_func(D2, sk['k12'])

        D1 = self._fl_func(D1, sk['ke3'])
        D2 = self._fl_inv_func(D2, sk['ke4'])

        D2 ^= self._f_func(D1, sk['k13']); D1 ^= self._f_func(D2, sk['k14'])
        D2 ^= self._f_func(D1, sk['k15']); D1 ^= self._f_func(D2, sk['k16'])
        D2 ^= self._f_func(D1, sk['k17']); D1 ^= self._f_func(D2, sk['k18'])

        D2 ^= sk['kw3']
        D1 ^= sk['kw4']

        return D2.to_bytes(8, byteorder='big') + D1.to_bytes(8, byteorder='big')

    def camellia_ctr(self, data: bytes, iv: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("IV must be exactly 16 bytes long.")
        counter_int = int.from_bytes(iv, byteorder='big')
        output = bytearray()
        for i in range(0, len(data), 16):
            counter_bytes = counter_int.to_bytes(16, byteorder='big')
            keystream_block = self.encrypt_block(counter_bytes)
            data_block = data[i:i+16]
            for b_data, b_key in zip(data_block, keystream_block):
                output.append(b_data ^ b_key)
            counter_int = (counter_int + 1) & Camellia.MASK128
        return bytes(output)


if __name__ == "__main__":
    # Official RFC 3713 test vector
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    pt  = bytes.fromhex("0123456789abcdeffedcba9876543210")
    expected = "67673138549669730857065648eabe43"

    c = Camellia(key)
    ct = c.encrypt_block(pt)
    print("Got:     ", ct.hex())
    print("Expected:", expected)
    print("MATCH:", ct.hex() == expected)