import json
# ייבוא הקבצים מתוך תיקיית הפרויקט שלך
import camellia
import rsa.py as rsa
import signature

class ShareLocationApp:
    def __init__(self):
        print("\n[+] מאתחל מערכת שיתוף מיקום מאובטחת ומייצר מפתחות...")
        # יצירת מפתחות אסימטריים (RSA) לצורך ההדגמה (עבור אליס ובוב)
        self.alice_public, self.alice_private = rsa.generate_keypair(61, 53)
        self.bob_public, self.bob_private = rsa.generate_keypair(67, 59)
        
        # מפתח סימטרי קבוע ל-Camellia (באורך 16 בתים / 128 סיביות)
        # בהתאם למפרט Camellia שתומך בבלוק ומפתח של 128 סיביות
        self.session_key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]

    def run_console(self):
        """ מפעיל קונסול אינטראקטיבי לקבלת מיקום, הצפנה ופענוח שלו """
        print("=" * 60)
        print("         מערכת סימולציית שיתוף מיקום מאובטח")
        print("=" * 60)
        
        while True:
            print("\n--- תפריט פעולות ---")
            print("1. הזן מיקום חדש ושלח בצורה מאובטחת")
            print("2. יציאה מהתוכנית")
            
            choice = input("בחר אפשרות (1-2): ").strip()
            
            if choice == '2':
                print("[!] יוצא מהתוכנית. להתראות!")
                break
                
            if choice == '1':
                try:
                    # 1. קבלת קלט מהמשתמש
                    latitude = input("הזן קו רוחב (Latitude, למשל 32.1133): ").strip()
                    longitude = input("הזן קו אורך (Longitude, למשל 34.8044): ").strip()
                    
                    if not latitude or not longitude:
                        print("[❌] שגיאה: חובה להזין ערכים!")
                        continue
                        
                    # 2. סימולציית צד א' - השולח (אליס) מצפין וחותם
                    packet = self._simulate_sender(latitude, longitude)
                    
                    # 3. הצגת המידע המוצפן על המסך (מה שעובר ברשת)
                    self._print_encrypted_packet(packet)
                    
                    input("\n לחץ על Enter כדי להעביר את החבילה לצד השני (בוב) ולבטל את ההצפנה...\n")
                    
                    # 4. סימולציית צד ב' - המקבל (בוב) מפענח ומאמת
                    self._simulate_receiver(packet)
                    
                except Exception as e:
                    print(f"[❌] שגיאה במהלך התהליך: {e}")
            else:
                print("[❌] בחירה לא חוקית, נסה שוב.")

    def _simulate_sender(self, lat, lon):
        """ צד השולח: אריזת הנתונים, חתימה דיגיטלית והצפנה """
        print("\n--- [צד א': השולח] מתחיל תהליך אבטחה וריפוד ---")
        
        # בניית מבנה הנתונים
        location_data = json.dumps({"lat": lat, "lon": lon})
        
        # א. יצירת חתימה דיגיטלית על ה-Hash של המיקום (באמצעות המפתח הפרטי של השולח)
        print("[+] מחשב חתימה דיגיטלית (Signature) בעזרת המפתח הפרטי של אליס...")
        loc_signature = signature.signature_encrypt(location_data, self.alice_private)
        
        # ב. הצפנת נתוני המיקום בעזרת מפתח סימטרי של Camellia
        print("[+] מצפין את נתוני המיקום באמצעות אלגוריתם Camellia...")
        encrypted_location = camellia.encrypt(self.session_key, location_data)
        
        # ג. הצפנת מפתח ה-Camellia עצמו בעזרת המפתח הציבורי של המקבל (RSA)
        print("[+] מצפין את מפתח ה-Camellia בעזרת המפתח הציבורי של בוב (RSA)...")
        key_as_str = ",".join(map(str, self.session_key))
        encrypted_session_key = rsa.encrypt(self.bob_public, key_as_str)
        
        # הרכבת חבילת המידע המלאה
        return {
            "encrypted_location": encrypted_location,
            "encrypted_key": encrypted_session_key,
            "signature": loc_signature
        }

    def _print_encrypted_packet(self, packet):
        """ מדפיס את המידע המוצפן כפי שהוא נראה 'באוויר' """
        print("\n" + "="*20 + " החבילה המוצפנת שעוברת ברשת " + "="*20)
        print(f"🔒 מיקום מוצפן (Camellia Ciphertext):\n   {packet['encrypted_location']}")
        print(f"🔒 מפתח סימטרי מוצפן (RSA Encrypted Key):\n   {packet['encrypted_key']}")
        print(f"🔏 חתימה דיגיטלית (Sender Signature):\n   {packet['signature']}")
        print("=" * 68)

    def _simulate_receiver(self, packet):
        """ צד המקבל: פענוח ואימות החבילה """
        print("--- [צד ב': המקבל] מקבל את החבילה ומתחיל ביטול הצפנה ---")
        
        # א. פענוח מפתח ה-Camellia בעזרת המפתח הפרטי של המקבל (RSA)
        print("[+] מפענח את מפתח ה-Camellia בעזרת המפתח הפרטי של בוב (RSA)...")
        decrypted_key_str = rsa.decrypt(self.bob_private, packet["encrypted_key"])
        session_key = [int(x) for x in decrypted_key_str.split(",")]
        
        # ב. ביטול הצפנת המיקום (פענוח) בעזרת מפתח ה-Camellia שחולץ
        print("[+] מפענח ומבטל את הצפנת המיקום באמצעות Camellia...")
        decrypted_location_json = camellia.decrypt(session_key, packet["encrypted_location"])
        
        # ג. אימות החתימה הדיגיטלית בעזרת המפתח הציבורי של השולח
        print("[+] מאמת את זהות השולח ואת שלמות המידע בעזרת המפתח הציבורי של אליס...")
        is_valid_signature = signature.signature_decrypt(
            decrypted_location_json, 
            packet["signature"], 
            self.alice_public
        )
        
        # ד. פלט סופי בהתאם לתוצאת האימות
        if is_valid_signature:
            print("[✓] הצלחה: החתימה אומתה! המידע אמין לחלוטין ולא שונה בדרך.")
            location = json.loads(decrypted_location_json)
            print(f"📍 המיקום המקורי שוחזר: קו רוחב {location['lat']}, קו אורך {location['lon']}")
        else:
            print("[❌] אזהרת אבטחה חמורה: אימות החתימה נכשל! המידע זוייף או שונה!")

# הרצת הקונסול
if __name__ == "__main__":
    app = ShareLocationApp()
    app.run_console()