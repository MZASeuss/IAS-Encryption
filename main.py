import streamlit as st
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA

DEFAULT_AES_KEY = "00112233445566778899aabbccddeeff"
DEFAULT_DES_KEY = "0123456789abcdef"

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

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

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
        public_key, private_key = generate_rsa_keys()
        st.text_area("Generated Public Key:", value=public_key.decode())
        st.text_area("Generated Private Key:", value=private_key.decode())
    else:
        ciphertext = st.text_input("Enter the ciphertext (in hex):")
        private_key_input = st.text_area("Enter the private key:")

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
                public_key = RSA.import_key(public_key)
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
                private_key = RSA.import_key(private_key_input)
                ciphertext_bytes = bytes.fromhex(ciphertext)
                plaintext = rsa_decrypt(ciphertext_bytes, private_key)
                st.write(f"Plaintext: {plaintext}")

    except Exception as e:
        st.error(f"Error: {e}")
