import hashlib
import rsa

def signature_encrypt(text, private_key):
    # 1. חישוב ה-Hash של הטקסט המקורי
    hash_object = hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    # 2. חתימה על ה-Hash בעזרת המפתח הפרטי (ולא הציבורי)
    # הערה: בספריות רבות הפונקציה rsa.sign עושה גם את ה-Hash לבד,
    # אך לצורך הדגמת הלוגיקה שלך - כאן חותמים על ה-Hash.
    signature = rsa.encrypt(private_key, hash_object)
    return signature

def signature_decrypt(text, signature, public_key):
    try:
        # 1. חישוב ה-Hash הנוכחי של הטקסט שהתקבל
        current_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
        
        # 2. שחזור: משתמשים ב-decrypt שלכם, אבל מעבירים את המפתח הציבורי!
        decrypted_hash = rsa.decrypt(public_key, signature)
        
        # 3. אימות: אם ה-Hash ששוחזר זהה ל-Hash הנוכחי - החתימה תקינה
        return decrypted_hash == current_hash
        
    except Exception:
        return False