import hashlib
import rsa.py as rsa

def signature_encrypt(text, private_key):
    # 1. חישוב ה-Hash של הטקסט המקורי
    hash_object = hashlib.sha256(text.encode('utf-8')).digest()
    
    # 2. חתימה על ה-Hash בעזרת המפתח הפרטי (ולא הציבורי)
    # הערה: בספריות רבות הפונקציה rsa.sign עושה גם את ה-Hash לבד,
    # אך לצורך הדגמת הלוגיקה שלך - כאן חותמים על ה-Hash.
    signature = rsa.sign(text.encode('utf-8'), private_key, 'SHA-256')
    return signature

def signature_decrypt(text, signature, public_key):
    try:
        # אימות החתימה מול הטקסט המקורי בעזרת המפתח הציבורי
        # הפונקציה הזו מחשבת את ה-Hash של ה-text, מפענחת את החתימה בעזרת
        # המפתח הציבורי, ומשווה ביניהם אוטומטית.
        rsa.verify(text.encode('utf-8'), signature, public_key)
        return True  # האימות הצליח
    except rsa.VerificationError:
        return False  # החתימה שגויה או שהטקסט שונה בדרך