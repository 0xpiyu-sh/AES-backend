# app.py
import os
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
# Allow your specific frontend URL in production, but allow all for local testing
CORS(app) 

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure 32-byte (256-bit) key from a string password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes = 256 bits
        salt=salt,
        iterations=480000, # High iteration count slows down brute-force attacks
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_engine(text: str, password: str) -> str:
    # 1. Generate a random salt to make the key derivation unique
    salt = os.urandom(16)
    
    # 2. Derive the AES-256 key
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # 3. Generate a random nonce (Initialization Vector) required by GCM
    nonce = os.urandom(12)
    
    # 4. Encrypt the data
    ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    
    # 5. Pack the salt, nonce, and ciphertext together so decryption is possible
    encrypted_payload = salt + nonce + ciphertext
    
    # 6. Encode to Base64 so it can be safely sent as a string in JSON
    return base64.b64encode(encrypted_payload).decode('utf-8')

def decrypt_engine(payload_b64: str, password: str) -> str:
    try:
        # 1. Decode the Base64 string back into raw bytes
        encrypted_payload = base64.b64decode(payload_b64)
        
        # 2. Extract the components (Salt: 16 bytes, Nonce: 12 bytes, Ciphertext: the rest)
        salt = encrypted_payload[:16]
        nonce = encrypted_payload[16:28]
        ciphertext = encrypted_payload[28:]
        
        # 3. Derive the exact same key using the extracted salt
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        
        # 4. Decrypt and verify the data
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
        
    except InvalidTag:
        raise ValueError("Authentication failed: Incorrect password or data was tampered with.")
    except Exception as e:
        raise ValueError("Decryption failed: Invalid payload format.")

@app.route('/api/cipher', methods=['POST'])
def process_cipher():
    data = request.get_json()
    
    if not data or 'text' not in data or 'keyword' not in data:
        return jsonify({"error": "Missing required parameters (text, keyword)"}), 400
        
    text = data['text']
    password = data['keyword']
    mode = data.get('mode', 'encrypt')
    
    if not text.strip() or not password.strip():
        return jsonify({"error": "Fields cannot be empty"}), 400

    try:
        if mode == 'encrypt':
            result = encrypt_engine(text, password)
        elif mode == 'decrypt': 
            result = decrypt_engine(text, password)
        else:
            return jsonify({"error": "Invalid mode"}), 400
            
        return jsonify({
            "status": "success",
            "mode": mode,
            "result": result
        }), 200
        
    except ValueError as ve:
        # Catch our specific decryption errors (like wrong password)
        return jsonify({"error": str(ve)}), 401
    except Exception as e:
        print(f"Server Error: {e}")
        return jsonify({"error": "Internal server processing error"}), 500

if __name__ == '__main__':
    print("Starting AES-256 API on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
