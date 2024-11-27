import streamlit as st
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA

DEFAULT_AES_KEY = "00112233445566778899aabbccddeeff"
DEFAULT_DES_KEY = "0123456789abcdef"

DEFAULT_RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GhPA12/UbHf9vOpd5bb
xnS9PvI2h1ZPVGZpHmtg3qERFw8Xx1KFYyWhO/60glSKVkp/NaW9uG3lqjB3hC+f
S/JI4OwT5PTNB9FiTBGFf2Rae8CgF2vo5wG9CaQU1m3djSZ0CkZApU5r0Hx/w5h4
NO0opN3Rwx5vIdOeFCmpBKoYr7BMPTO12FovI95nrt1z/10wHjogIb7WZbhX0lgE
cf4H+gOV2IR6+eCP5DZUtNWeNIfUnvgRE6QC8fCZRS7+hGB3zREoAsIEBr0gxMnR
0AQkRQ6mBKsdXGMiHhoYZvn46ThjaKSMvsIHxwxJFPQNKlmH+rN4zWnY3ptG05k+
6wIDAQAB
-----END PUBLIC KEY-----"""

DEFAULT_RSA_PRIVATE_KEY ="""-----BEGIN PRIVATE KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GhPA12/UbHf9vOpd5bb
xnS9PvI2h1ZPVGZpHmtg3qERFw8Xx1KFYyWhO/60glSKVkp/NaW9uG3lqjB3hC+f
S/JI4OwT5PTNB9FiTBGFf2Rae8CgF2vo5wG9CaQU1m3djSZ0CkZApU5r0Hx/w5h4
NO0opN3Rwx5vIdOeFCmpBKoYr7BMPTO12FovI95nrt1z/10wHjogIb7WZbhX0lgE
cf4H+gOV2IR6+eCP5DZUtNWeNIfUnvgRE6QC8fCZRS7+hGB3zREoAsIEBr0gxMnR
0AQkRQ6mBKsdXGMiHhoYZvn46ThjaKSMvsIHxwxJFPQNKlmH+rN4zWnY3ptG05k+
6wIDAQAB
-----END PRIVATE KEY-----"""

# AES functions
def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, nonce

def aes_decrypt(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext

# DES functions
def des_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = message + " " * (8 - len(message) % 8)
    ciphertext = cipher.encrypt(padded_message.encode())
    return ciphertext

def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext).decode()
    return padded_message.strip()

# RSA functions
def rsa_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext

# Streamlit app
st.title("Multiple Encryption")
st.write("Hi, Sir Corton")

method = st.selectbox("Method", ("Encrypt", "Decrypt"))
encryption_type = st.selectbox("Type", ("AES", "DES", "RSA"))

if encryption_type == "AES":
    st.subheader(f"AES {method}")
    key = st.text_input("Enter the 16-byte key (in hex):", value=DEFAULT_AES_KEY)
    key_bytes = bytes.fromhex(key)

    if method == "Encrypt":
        message = st.text_input("Enter the message:")
    else:
        nonce = st.text_input("Enter the nonce (in hex):")
        ciphertext = st.text_input("Enter the ciphertext (in hex):")

elif encryption_type == "DES":
    st.subheader(f"DES {method}")
    key = st.text_input("Enter the 8-byte key (in hex):", value=DEFAULT_DES_KEY)
    key_bytes = bytes.fromhex(key)

    if method == "Encrypt":
        message = st.text_input("Enter the message:")
    else:
        ciphertext = st.text_input("Enter the ciphertext (in hex):")

elif encryption_type == "RSA":
    st.subheader(f"RSA {method}")
    if method == "Encrypt":
        message = st.text_input("Enter the message:")
        public_key_pem = st.text_area("Enter the public key (PEM format):" , value= DEFAULT_RSA_PUBLIC_KEY)
        try:
            public_key = RSA.import_key(public_key_pem)
        except ValueError:
            st.error("Invalid public key format. Please provide a valid PEM-formatted key.")
    else:
        ciphertext = st.text_input("Enter the ciphertext (in hex):")
        private_key_pem = st.text_area("Enter the private key (PEM format):" , value= DEFAULT_RSA_PRIVATE_KEY)
        try:
            private_key = RSA.import_key(private_key_pem)
        except ValueError:
            st.error("Invalid private key format. Please provide a valid PEM-formatted key.")

if st.button("Submit"):
    try:
        if method == "Encrypt":
            if encryption_type == "AES":
                ciphertext, nonce = aes_encrypt(message, key_bytes)
                st.write(f"Ciphertext: {ciphertext.hex()}")
                st.write(f"Nonce: {nonce.hex()}")
            elif encryption_type == "DES":
                ciphertext = des_encrypt(message, key_bytes)
                st.write(f"Ciphertext: {ciphertext.hex()}")
            elif encryption_type == "RSA":
                ciphertext = rsa_encrypt(message, public_key)
                st.write(f"Ciphertext: {ciphertext.hex()}")

        elif method == "Decrypt":
            if encryption_type == "AES":
                nonce_bytes = bytes.fromhex(nonce)
                ciphertext_bytes = bytes.fromhex(ciphertext)
                plaintext = aes_decrypt(ciphertext_bytes, key_bytes, nonce_bytes)
                st.write(f"Plaintext: {plaintext}")
            elif encryption_type == "DES":
                ciphertext_bytes = bytes.fromhex(ciphertext)
                plaintext = des_decrypt(ciphertext_bytes, key_bytes)
                st.write(f"Plaintext: {plaintext}")
            elif encryption_type == "RSA":
                ciphertext_bytes = bytes.fromhex(ciphertext)
                plaintext = rsa_decrypt(ciphertext_bytes, private_key)
                st.write(f"Plaintext: {plaintext}")

    except Exception as e:
        st.error(f"Error: {e}")
