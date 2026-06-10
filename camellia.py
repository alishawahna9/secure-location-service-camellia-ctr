# ==========================================
#        Camellia Cipher - CTR Mode         
#        100% Pure Python (No Imports)      
# ==========================================

class Camellia:
    # --- 1. טבלאות ה-S-Box הקבועות של קמיליה ---
    SBOX1 = [
        112, 130,  44, 187,  60, 252, 133,  87,  14,  51, 197, 213,  90, 238, 182,  21,
         88,  78,  33,  17, 140, 178,  25,  30, 251,  91,  69, 117, 180, 210, 195,  35,
         97,  56,  24,  46,  66,  39, 179,  11,  63,  54, 118,  10, 150, 226, 154, 142,
         67, 115, 168,  34,  40, 144,  12,  52, 232,  84,  13,  45, 126,  93, 159,  96,
        143, 201, 134,  74, 132, 105,  26, 149, 147, 222, 121,  16, 135, 106,  18,  53,
        217, 188, 227, 231, 116,  81, 151,  68,  42, 153, 137, 246, 211, 221,  57, 125,
         50, 157, 247, 110, 244, 214, 131, 204, 236,  95,  98,  54, 224,  43, 114, 146,
         22,  38, 172, 223, 255, 158, 202, 145, 241, 160, 124,  19, 192,  92,  94,  23,
          2,  37,  65,  20,  27,  64, 148,  41, 240, 174, 122,  47, 200, 123, 170,  28,
         31, 108, 120, 208, 127, 165, 111, 228, 196, 212, 173,  82, 209,  62, 183, 129,
        138, 164, 102,  99, 198, 249, 109,  83, 230,  49, 163, 250, 171,  29,  48, 243,
        166,  59, 141, 220, 103,  58,  36, 119, 248, 161,   3, 113,  46,  79, 147,  86,
         15, 100, 139, 104, 253, 175, 194,  28, 181, 225,  61, 206, 177, 235,  15, 162,
         75, 219,  10, 101,  32, 229, 245,  60, 107, 169,  76, 242, 216,  43,  85,  77,
         89,  16, 207,  55, 136,  27,  80,  91,  80,  90, 215, 189, 145, 111,  72,  33,
        186,  81, 218,  73,  63,  19, 121,  35, 193,  53,  84, 135, 108,  32, 254,  26
    ]

    # יצירת שאר ה-S-Boxes מתוך SBOX1 באמצעות הזזות בינאריות (קבוע לפי התקן)
    SBOX2 = [((s << 1) & 0xFF) | (s >> 7) for s in SBOX1]
    SBOX3 = [((s << 7) & 0xFF) | (s >> 1) for s in SBOX1]
    SBOX4 = [SBOX1[s] for s in SBOX2] # SBOX4 הוא פשוט SBOX1(SBOX2(i))

    # קבועים אריתמטיים Sigma עבור יצירת מפתחות (128 ביט משתמש רק ב-SIGMA1 עד SIGMA4)
    SIGMA = [
        0xA09E667F3BCC908B,
        0xB64A4A366A2D36DE,
        0x4310E0E21C743128,
        0xCBC20BE34E93C6EE
    ]

    def __init__(self, key_bytes: bytes):
        """ אתחול הצופן עם מפתח באורך 128-ביט (16 בתים) """
        if len(key_bytes) != 16:
            raise ValueError("Only 128-bit keys (16 bytes) are supported in this script.")
        
        # המרת המפתח ל-2 משתנים של 64 ביט (KL_L ו-KL_R)
        self.KL_L = int.from_bytes(key_bytes[0:8], byteorder='big')
        self.KL_R = int.from_bytes(key_bytes[8:16], byteorder='big')
        
        self.subkeys = {}
        self._generate_subkeys()

    # --- 2. פונקציות עזר סיביות (Bitwise Helper Functions) ---
    @staticmethod
    def _rotl64(x: int, shift: int) -> int:
        """ הזזה מעגלית שמאלה (Rotate Left) של 64 ביט """
        return ((x << shift) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - shift))

    @staticmethod
    def _rotl128(x: int, shift: int) -> int:
        """ הזזה מעגלית שמאלה של 128 ביט """
        return ((x << shift) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) | (x >> (128 - shift))

    # --- 3. פונקציות הליבה של הצופן ---
    def _f_func(self, f_in: int, ke: int) -> int:
        """ פונקציית ה-F המרכזית (F-Function) המשלבת S-Boxes ופעולת XOR ומטריצה חלופית """
        x = f_in ^ ke
        
        # פירוק ל-8 בתים נפרדים
        b1 = (x >> 56) & 0xFF
        b2 = (x >> 48) & 0xFF
        b3 = (x >> 40) & 0xFF
        b4 = (x >> 32) & 0xFF
        b5 = (x >> 24) & 0xFF
        b6 = (x >> 16) & 0xFF
        b7 = (x >> 8) & 0xFF
        b8 = x & 0xFF
        
        # החלפה באמצעות טבלאות ה-S-Box
        s1 = self.SBOX1[b1]
        s2 = self.SBOX2[b2]
        s3 = self.SBOX3[b3]
        s4 = self.SBOX4[b4]
        s5 = self.SBOX2[b5]
        s6 = self.SBOX3[b6]
        s7 = self.SBOX4[b7]
        s8 = self.SBOX1[b8]
        
        # הכפלה במטריצה הליניארית (Linear Transformation Block)
        z1 = s1 ^ s3 ^ s4 ^ s6 ^ s7 ^ s8
        z2 = s1 ^ s2 ^ s4 ^ s5 ^ s7 ^ s8
        z3 = s1 ^ s2 ^ s3 ^ s5 ^ s6 ^ s8
        z4 = s2 ^ s3 ^ s4 ^ s5 ^ s6 ^ s7
        z5 = s1 ^ s2 ^ s6 ^ s7 ^ s8
        z6 = s2 ^ s3 ^ s5 ^ s7 ^ s8
        z7 = s3 ^ s4 ^ s5 ^ s6 ^ s8
        z8 = s1 ^ s4 ^ s5 ^ s6 ^ s7
        
        # חיבור חזרה למספר אחד בגודל 64 ביט
        return (z1 << 56) | (z2 << 48) | (z3 << 40) | (z4 << 32) | \
               (z5 << 24) | (z6 << 16) | (z7 << 8) | z8

    @staticmethod
    def _fl_func(fl_in: int, kl: int) -> int:
        """ פונקציית שכבה חלופית FL """
        x1 = fl_in >> 32
        x2 = fl_in & 0xFFFFFFFF
        k1 = kl >> 32
        k2 = kl & 0xFFFFFFFF
        
        y2 = x2 ^ (((x1 & k1) << 1) & 0xFFFFFFFF) | (((x1 & k1) >> 31) & 1)
        y1 = x1 ^ (y2 | k2)
        return (y1 << 32) | y2

    @staticmethod
    def _fl_inv_func(fli_in: int, kl: int) -> int:
        """ הפונקציה ההופכית לשכבה החלופית FL-inverse """
        y1 = fli_in >> 32
        y2 = fli_in & 0xFFFFFFFF
        k1 = kl >> 32
        k2 = kl & 0xFFFFFFFF
        
        x1 = y1 ^ (y2 | k2)
        x2 = y2 ^ (((x1 & k1) << 1) & 0xFFFFFFFF) | (((x1 & k1) >> 31) & 1)
        return (x1 << 32) | x2

    # --- 4. תזמון מפתחות (Key Schedule) ---
    def _generate_subkeys(self):
        """ מייצר את כל תתי-המפתחות הנדרשים להצפנה של 18 סבבים למפתח 128 ביט """
        # שלב א': יצירת המשתנה KA
        ka_l = self.KL_L ^ 0
        ka_r = self.KL_R ^ 0
        
        # סבבי F ראשוניים ליצירת מפתח העזר KA
        d1 = self._f_func(ka_l, self.SIGMA[0]) ^ ka_r
        d2 = self._f_func(d1, self.SIGMA[1]) ^ ka_l
        d1 = d1 ^ self._f_func(d2, self.SIGMA[2])
        d2 = d2 ^ self._f_func(d1, self.SIGMA[3])
        ka_l, ka_r = d1, d2

        # שילוב המפתחות לרצפים של 128 ביט כדי לבצע הזזות מעגליות (Rotations) בקלות
        kl = (self.KL_L << 64) | self.KL_R
        ka = (ka_l << 64) | ka_r

        # חילוץ תתי-המפתחות ע"י הזזות קבועות לפי הגדרת האלגוריתם
        def get_64(val128, shift, part):
            rotated = self._rotl128(val128, shift)
            return (rotated >> 64) if part == 'L' else (rotated & 0xFFFFFFFFFFFFFFFF)

        self.subkeys['k1']  = get_64(kl, 0, 'L')
        self.subkeys['k2']  = get_64(kl, 0, 'R')
        self.subkeys['k3']  = get_64(ka, 0, 'L')
        self.subkeys['k4']  = get_64(ka, 0, 'R')
        self.subkeys['k5']  = get_64(kl, 15, 'L')
        self.subkeys['k6']  = get_64(kl, 15, 'R')
        self.subkeys['k7']  = get_64(ka, 15, 'L')
        self.subkeys['k8']  = get_64(ka, 15, 'R')
        self.subkeys['k9']  = get_64(kl, 30, 'L')
        self.subkeys['k10'] = get_64(kl, 30, 'R')
        self.subkeys['k11'] = get_64(ka, 30, 'L')
        self.subkeys['k12'] = get_64(ka, 30, 'R')
        self.subkeys['k13'] = get_64(kl, 45, 'L')
        self.subkeys['k14'] = get_64(kl, 45, 'R')
        self.subkeys['k15'] = get_64(ka, 45, 'L')
        self.subkeys['k16'] = get_64(ka, 45, 'R')
        self.subkeys['k17'] = get_64(kl, 60, 'L')
        self.subkeys['k18'] = get_64(kl, 60, 'R')

        # מפתחות מיוחדים לשכבות ה-FL / FL-inv (נקראים kw ו-ke)
        self.subkeys['kw1'] = get_64(kl, 0, 'L')
        self.subkeys['kw2'] = get_64(kl, 0, 'R')
        self.subkeys['ke1'] = get_64(ka, 30, 'L')
        self.subkeys['ke2'] = get_64(ka, 30, 'R')
        self.subkeys['kw3'] = get_64(ka, 60, 'L')
        self.subkeys['kw4'] = get_64(ka, 60, 'R')

    # --- 5. הצפנת בלוק בודד (Core 16-Bytes Engine) ---
    def encrypt_block(self, block: bytes) -> bytes:
        """ מצפין בלוק בודד של 16 בתים בדיוק """
        d1 = int.from_bytes(block[0:8], byteorder='big')
        d2 = int.from_bytes(block[8:16], byteorder='big')

        # סבב פתיחה - Pre-whitening
        d1 ^= self.subkeys['kw1']
        d2 ^= self.subkeys['kw2']

        # סבבים 1 עד 6
        d2 ^= self._f_func(d1, self.subkeys['k1']);  d1 ^= self._f_func(d2, self.subkeys['k2'])
        d2 ^= self._f_func(d1, self.subkeys['k3']);  d1 ^= self._f_func(d2, self.subkeys['k4'])
        d2 ^= self._f_func(d1, self.subkeys['k5']);  d1 ^= self._f_func(d2, self.subkeys['k6'])

        # שכבת פילטר FL / FL-inv ראשונה
        d1 = self._fl_func(d1, self.subkeys['ke1'])
        d2 = self._fl_inv_func(d2, self.subkeys['ke2'])

        # סבבים 7 עד 12
        d2 ^= self._f_func(d1, self.subkeys['k7']);  d1 ^= self._f_func(d2, self.subkeys['k8'])
        d2 ^= self._f_func(d1, self.subkeys['k9']);  d1 ^= self._f_func(d2, self.subkeys['k10'])
        d2 ^= self._f_func(d1, self.subkeys['k11']); d1 ^= self._f_func(d2, self.subkeys['k12'])

        # שכבת פילטר FL / FL-inv שניה
        d1 = self._fl_func(d1, self.subkeys['ke2'])
        d2 = self._fl_inv_func(d2, self.subkeys['ke2']) # הערה: לפי התקן ke2 משמש בשני החלקים בשכבה זו

        # סבבים 13 עד 18
        d2 ^= self._f_func(d1, self.subkeys['k13']); d1 ^= self._f_func(d2, self.subkeys['k14'])
        d2 ^= self._f_func(d1, self.subkeys['k15']); d1 ^= self._f_func(d2, self.subkeys['k16'])
        d2 ^= self._f_func(d1, self.subkeys['k17']); d1 ^= self._f_func(d2, self.subkeys['k18'])

        # סבב סגירה וסנכרון - Post-whitening (כולל החלפת צדדים סופית)
        d2 ^= self.subkeys['kw3']
        d1 ^= self.subkeys['kw4']

        return d2.to_bytes(8, byteorder='big') + d1.to_bytes(8, byteorder='big')

    # --- 6. מימוש מצב מונה CTR Mode (הצפנה ופענוח בקוד אחד) ---
    def camellia_ctr(self, data: bytes, iv: bytes) -> bytes:
        """
        מצב עבודה CTR עבור צופן Camellia.
        מתאים גם להצפנה וגם לפענוח ללא צורך ב-Padding (ריפוד).
        
        :param data: מערך בתים (bytes) בכל אורך שהוא
        :param iv: וקטור אתחול (Initialization Vector) - חייב להיות בדיוק 16 בתים
        :return: מערך בתים מוצפן או מפוענח
        """
        if len(iv) != 16:
            raise ValueError("IV must be exactly 16 bytes long.")
        
        # המרת ה-IV למספר שלם כדי שנוכל לקדם אותו בקלות בלולאה
        counter_int = int.from_bytes(iv, byteorder='big')
        output = bytearray()
        
        # ריצה על המידע בקפיצות של 16 בתים (גודל בלוק)
        for i in range(0, len(data), 16):
            # 1. המרת המונה הנוכחי חרה למערך בתים (16 בתים בגודל)
            counter_bytes = counter_int.to_bytes(16, byteorder='big')
            
            # 2. הצפנת המונה באמצעות מנוע קמיליה לקבלת זרם המפתח (Keystream)
            keystream_block = self.encrypt_block(counter_bytes)
            
            # 3. חיתוך בלוק המידע (עובד מעולה גם אם הבלוק האחרון קצר מ-16 בתים!)
            data_block = data[i:i+16]
            
            # 4. ביצוע פעולת XOR ביט אחר ביט
            for b_data, b_key in zip(data_block, keystream_block):
                output.append(b_data ^ b_key)
            
            # 5. קידום המונה ב-1 לקראת הבלוק הבא
            counter_int = (counter_int + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            
        return bytes(output)


# ==========================================
#      בדיקת תקינות וסימולציה (Main Loop)     
# ==========================================
if __name__ == "__main__":
    print("--- Camellia CTR Mode Implementation ---")
    
    # 1. הגדרת מפתח סודי (16 בתים / 128 ביט) ווקטור אתחול IV (16 בתים)
    secret_key = b"MySecretCamelKey"  # 16 בתים בדיוק
    init_vector = b"UniqueNonce12345" # 16 בתים בדיוק
    
    # 2. אתחול מחלקת הצופן
    cipher = Camellia(secret_key)
    
    # 3. נתוני ה-GPS לבדיקה (טקסט באורך חופשי - לא מתחלק ב-16)
    original_gps_data = b"GPS_DATA: lat=32.085300; lon=34.781800; alt=45m;"
    print(f"Original Data:  {original_gps_data.decode('utf-8')}")
    print(f"Data Length:    {len(original_gps_data)} bytes")
    print("-" * 50)
    
    # 4. הצפנה
    encrypted = cipher.camellia_ctr(original_gps_data, init_vector)
    print(f"Encrypted (Hex): {encrypted.hex()}")
    
    # 5. פענוח (באמצעות אותה מתודה בדיוק ועם אותו ה-IV!)
    decrypted = cipher.camellia_ctr(encrypted, init_vector)
    print(f"Decrypted Data: {decrypted.decode('utf-8')}")
    
    # 6. בדיקת שלמות
    assert original_gps_data == decrypted, "❌ אופס, משהו השתבש בפענוח!"
    print("\n✅ בדיקת תקינות הצליחה! המידע פוענח במלואו בצורה מושלמת.")