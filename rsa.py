import math

# פונקציה למציאת המפתח הפרטי d (ההופכי הכפלי המודולרי)
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('ההופכי הכפלי המודולרי אינו קיים')
    else:
        return x % phi

# --- שלב 1: יצירת המפתחות ---
def generate_keypair(p, q):
    if p == q:
        raise ValueError('p ו-q חייבים להיות שונים!')
        
    # חישוב n
    n = p * q
    
    # חישוב (phi(n
    phi = (p - 1) * (q - 1)
    
    # בחירת e כך שיהיה זר ל-(phi(n
    e = 65537
    if math.gcd(e, phi) != 1:
        # אם 65537 לא זר (בגלל מספרים קטנים שבחרנו), נמצא e אחר
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
            
    # חישוב d (המפתח הפרטי)
    d = mod_inverse(e, phi)
    
    # החזרת זוג המפתחות: (ציבורי), (פרטי)
    return ((e, n), (d, n))

# --- שלב 2: הצפנה ---
def encrypt(public_key, plaintext):
    e, n = public_key
    # המרת כל תו בטקסט לערך ה-ASCII שלו והצפנתו מודולו n
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

# --- שלב 3: פענוח ---
def decrypt(private_key, ciphertext):
    d, n = private_key
    # פענוח כל מספר חזרה לערך ה-ASCII שלו והמרתו לתו
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

# === הרצה והדגמה ===
if __name__ == '__main__':
    # נבחר שני מספרים ראשוניים (בדוגמה אמיתית הם צריכים להיות ענקיים)
    p = 61
    q = 53
    
    print(f"1. בחירת מספרים ראשוניים: p={p}, q={q}")
    public_key, private_key = generate_keypair(p, q)
    
    print(f"2. מפתח ציבורי (e, n): {public_key}")
    print(f"3. מפתח פרטי (d, n): {private_key}\n")
    
    # הטקסט להצפנה
    message = "Hello RSA"
    print(f"ההודעה המקורית: '{message}'")
    
    # ביצוע הצפנה
    encrypted_msg = encrypt(public_key, message)
    print(f"הטקסט המוצפן (מערך מספרים): {encrypted_msg}")
    
    # ביצוע פענוח
    decrypted_msg = decrypt(private_key, encrypted_msg)
    print(f"הטקסט המפוענח: '{decrypted_msg}'")