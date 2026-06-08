# base switching s1 table for Camellia cipher implementation
SBOX_S1 = [
    112, 130,  44, 187,  60,  16, 133,  40, 153,   4, 121,  18,  95,  86, 252, 171,
     12, 239, 142,  13,  74,  47, 244, 120, 234,  75, 231,  45,  14,  64,  53,  71,
    200,  88,   9,  76, 222, 127, 219, 114, 163, 107, 147,  17,  59, 122, 160, 226,
    181, 131,  49, 182,  23,   2,  94,  68, 111, 238,  42, 124, 212,  52,  14, 141,
     19, 211, 156,  33, 115, 193,  20, 164, 102,  67, 216,  43, 150, 198, 154, 145,
    105,   0, 172, 116, 215, 148, 132,  22,  36, 137, 125,  63,  96,  31, 159,  83,
    209,   7,  41,  61,  24,  93,  21, 225, 242,  69,  17, 123, 126, 221,  30, 201,
     80,  35, 161,  26, 146, 167, 151,  50,  48,  46,  13, 197,  28, 119,  62, 169,
    157, 168,   8,  87, 214, 134,  57, 100, 184, 220, 104, 117, 138, 110, 183, 101,
     27,  65, 129, 213,  58, 250, 251, 243, 224,  54, 245, 128, 228, 185,  56, 254,
    241,  15, 230, 135,  32, 109, 113,  85,  79, 118, 139, 247,  72,   5,   3,  25,
     81, 162, 165, 155, 194, 210,   1,   6, 240, 223,  70,  73,  82, 199, 246, 195,
    217,  55,  84, 176, 227,  17,  66,  90, 144,  51, 179, 249, 235, 248, 233, 136,
    205,  11, 106, 103, 203,  98,  34, 186,  89, 108, 196,  78,  37, 208,  91,  38,
    174, 202,   0, 180, 229,  19, 131,  77,  64,  39, 140,  29, 218, 189, 143,   1,
     97, 206, 170, 237, 232, 110, 207, 177,  18,  54, 236,  99, 149,  26, 173, 158
]

def _sbox_s2(x): return (SBOX_S1[x] << 1) & 0xFF | (SBOX_S1[x] >> 7)
def _sbox_s3(x): return (SBOX_S1[x] << 7) & 0xFF | (SBOX_S1[x] >> 1)
def _sbox_s4(x): return SBOX_S1[(SBOX_S1[x] << 1) & 0xFF | (SBOX_S1[x] >> 7)]

# הקבועים הקריפטוגרפיים הסטטיים (SIGMA) עבור תזמון המפתחות
SIGMA = [
    0x0A001A012A023A03,
    0x4A045A056A067A07,
    0x8A089A09AA0AAA0B,
    0xC00C0A0DDA0EEA0F,
    0x5015015015015015,
    0xA02A02A02A02A02A
]



# rotate the 64-bit value to the left by the specified number of bits
def _left_rotate_64(value, shift):
    """rotate the 64-bit value to the left by the specified number of bits"""
    shift = shift % 64
    if shift == 0:
        return value
    """rotate the 64 bits to the left and delete the bits that overflowed on the left, then add them to the right"""
    return ((value << shift) & 0xFFFFFFFFFFFFFFFF) | (value >> (64 - shift))

def _fl_function(x, flk):
    """פונקציית העזר FL המשמשת בין סבבי הפייסטל המרכזיים"""
    xl = (x >> 32) & 0xFFFFFFFF
    xr = x & 0xFFFFFFFF
    flkl = (flk >> 32) & 0xFFFFFFFF
    flkr = flk & 0xFFFFFFFF
    
    xr = xr ^ _left_rotate_64((xl & flkl), 1)
    xl = xl ^ (xr | flkr)
    return (xl << 32) | xr

def _fl_inv_function(y, flk):
    """פונקציית העזר ההפוכה FL-inverse"""
    yl = (y >> 32) & 0xFFFFFFFF
    yr = y & 0xFFFFFFFF
    flkl = (flk >> 32) & 0xFFFFFFFF
    flkr = flk & 0xFFFFFFFF
    
    yl = yl ^ (yr | flkr)
    yr = yr ^ _left_rotate_64((yl & flkl), 1)
    return (yl << 32) | yr



#Camellia
class Camellia:
    def __init__(self, master_key):
        """
        contructor for Camellia cipher implementation. Takes a 128-bit (16-byte) master key and generates the 26 subkeys needed for encryption according to RFC 3713.
        """
        if len(master_key) != 16:
            raise ValueError("Master key must be exactly 16 bytes long.")
        """initialize the subkeys array and generate the subkeys from the master key using the key schedule algorithm"""
        """create an array of 26 subkeys (each 64 bits) and generate the subkeys from the master key using the key schedule algorithm"""
        self.sub_keys = [0] * 26  
        self._generate_subkeys(master_key)

    def _f_function(self, x, round_key):
        """xor the input with the round key"""
        fed = x ^ round_key
        """apply the S-boxes to the 8 bytes of the fed value and combine the results using XOR operations to produce the output"""
        t1 = (fed >> 56) & 0xFF
        t2 = (fed >> 48) & 0xFF
        t3 = (fed >> 40) & 0xFF
        t4 = (fed >> 32) & 0xFF
        t5 = (fed >> 24) & 0xFF
        t6 = (fed >> 16) & 0xFF
        t7 = (fed >> 8) & 0xFF
        t8 = fed & 0xFF

        z1 = SBOX_S1[t1]
        z2 = _sbox_s2(t2)
        z3 = _sbox_s3(t3)
        z4 = _sbox_s4(t4)
        z5 = _sbox_s4(t5)
        z6 = SBOX_S1[t6]
        z7 = _sbox_s2(t7)
        z8 = _sbox_s3(t8)

        y1 = z1 ^ z3 ^ z4 ^ z6 ^ z7 ^ z8
        y2 = z1 ^ z2 ^ z4 ^ z5 ^ z7 ^ z8
        y3 = z1 ^ z2 ^ z3 ^ z5 ^ z6 ^ z8
        y4 = z2 ^ z3 ^ z4 ^ z5 ^ z6 ^ z7
        y5 = z1 ^ z2 ^ z6 ^ z7 ^ z8
        y6 = z2 ^ z3 ^ z5 ^ z7 ^ z8
        y7 = z3 ^ z4 ^ z5 ^ z6 ^ z8
        y8 = z1 ^ z4 ^ z5 ^ z6 ^ z7

        output = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | \
                 (y5 << 24) | (y6 << 16) | (y7 << 8)  | y8
        return output

    def _generate_subkeys(self, master_key):
        """גזירת 26 תת-המפתחות מתוך מפתח ה-128 ביט לפי תקן RFC 3713"""
        # פירוק המפתח הראשי לשני חצאים של 64 ביט (KL)
        k_l = int.from_bytes(master_key[0:16], byteorder='big')
        kl = (k_l >> 64) & 0xFFFFFFFFFFFFFFFF
        kr = k_l & 0xFFFFFFFFFFFFFFFF
        
        # יצירת מפתח עזר קריפטוגרפי KA על ידי הפעלת פונקציית ה-F עם קבועי SIGMA
        d1 = kl ^ kr
        d2 = self._f_function(d1, SIGMA[0]) ^ kl
        d3 = self._f_function(d2, SIGMA[1]) ^ kr
        d4 = d3 ^ kl
        d5 = self._f_function(d4, SIGMA[2])
        ka_l = d2 ^ d5
        ka_r = d3 ^ self._f_function(ka_l, SIGMA[3])
        
        ka = (ka_l << 64) | ka_r
        kal = (ka >> 64) & 0xFFFFFFFFFFFFFFFF
        kar = ka & 0xFFFFFFFFFFFFFFFF

        # גזירת תת-המפתחות על בסיס הזזות מעגליות קבועות של KL ו-KA
        self.sub_keys[0] = kl                                # kw1
        self.sub_keys[1] = kr                                # kw2
        self.sub_keys[2] = (_left_rotate_64(kl, 0))          # k1
        self.sub_keys[3] = (_left_rotate_64(kr, 0))          # k2
        self.sub_keys[4] = (_left_rotate_64(kl, 15))         # k3
        self.sub_keys[5] = (_left_rotate_64(kr, 15))         # k4
        self.sub_keys[6] = (_left_rotate_64(kl, 30))         # k5
        self.sub_keys[7] = (_left_rotate_64(kr, 30))         # k6
        self.sub_keys[8] = (_left_rotate_64(kal, 0))         # ke1
        self.sub_keys[9] = (_left_rotate_64(kar, 0))         # ke2
        self.sub_keys[10] = (_left_rotate_64(kl, 45))        # k7
        self.sub_keys[11] = (_left_rotate_64(kr, 45))        # k8
        self.sub_keys[12] = (_left_rotate_64(kl, 60))        # k9
        self.sub_keys[13] = (_left_rotate_64(kar, 15))       # k10
        self.sub_keys[14] = (_left_rotate_64(kal, 30))       # k11
        self.sub_keys[15] = (_left_rotate_64(kr, 60))        # k12
        self.sub_keys[16] = (_left_rotate_64(kal, 45))       # ke3
        self.sub_keys[17] = (_left_rotate_64(kar, 45))       # ke4
        self.sub_keys[18] = (_left_rotate_64(kl, 77))        # k13
        self.sub_keys[19] = (_left_rotate_64(kr, 77))        # k14
        self.sub_keys[20] = (_left_rotate_64(kal, 60))       # k15
        self.sub_keys[21] = (_left_rotate_64(kar, 60))       # k16
        self.sub_keys[22] = (_left_rotate_64(kl, 94))        # k17
        self.sub_keys[23] = (_left_rotate_64(kr, 94))        # k18
        self.sub_keys[24] = (_left_rotate_64(kal, 111))      # kw3
        self.sub_keys[25] = (_left_rotate_64(kar, 111))      # kw4

    def encrypt_block(self, plaintext_block):
        """
        הצפנת בלוק גלוי בודד של 16 בתים (128 סיביות).
        מריץ את 18 הסבבים המלאים של רשת הפייסטל ופונקציות ה-FL.
        """
        if len(plaintext_block) != 16:
            raise ValueError("Plaintext block must be exactly 16 bytes long.")

        # 1. פירוק הבלוק לחצאים והמרה ל-int (Big-Endian)
        left = int.from_bytes(plaintext_block[0:8], byteorder='big')
        right = int.from_bytes(plaintext_block[8:16], byteorder='big')

        # שלב Pre-whitening
        left ^= self.sub_keys[0]
        right ^= self.sub_keys[1]

        # סבבים 1 עד 6
        for r in range(0, 6):
            if r % 2 == 0:
                left ^= self._f_function(right, self.sub_keys[2 + r])
            else:
                right ^= self._f_function(left, self.sub_keys[2 + r])

        # פונקציות הכללה FL / FL-inverse לאחר סבב 6
        left = _fl_function(left, self.sub_keys[8])
        right = _fl_inv_function(right, self.sub_keys[9])

        # סבבים 7 עד 12
        for r in range(0, 6):
            if r % 2 == 0:
                left ^= self._f_function(right, self.sub_keys[10 + r])
            else:
                right ^= self._f_function(left, self.sub_keys[10 + r])

        # פונקציות הכללה FL / FL-inverse לאחר סבב 12
        left = _fl_function(left, self.sub_keys[16])
        right = _fl_inv_function(right, self.sub_keys[17])

        # סבבים 13 עד 18
        for r in range(0, 6):
            if r % 2 == 0:
                left ^= self._f_function(right, self.sub_keys[18 + r])
            else:
                right ^= self._f_function(left, self.sub_keys[18 + r])

        # שלב Post-whitening והחלפה סופית (Final Swap)
        right ^= self.sub_keys[24]
        left ^= self.sub_keys[25]

        # איחוד והמרה חזרה למערך של 16 בתים
        ciphertext = bytearray(16)
        ciphertext[0:8] = right.to_bytes(8, byteorder='big')
        ciphertext[8:16] = left.to_bytes(8, byteorder='big')
        
        return bytes(ciphertext)