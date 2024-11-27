import streamlit as st
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


DEFAULT_AES_KEY = "00112233445566778899aabbccddeeff" 
DEFAULT_DES_KEY = "0123456789abcdef" 

DEFAULT_RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7vLVGzhmLSc7fMWhcJ7m
7iKD2FuHP/mkEktQpDyYO5YY3nH8lvTAsR8Yf0U41VZpN5O8Nk3Lw8WbOT9QuAHD
Pnp0ZbIMrvh6G/WmUMqTka/ekVWmFWJoM8P7dK8eP39FRzBN3RZzS+bwgjpJdS1g
lQQ6Vfp60/uUMKQm29KsZ9sQIgYJOrVtYuzG+lITM0afRn+7K6gpXBC1nRruXXwB
PxS6VJeU8XBXqfOtqTgflR6xwW3E2Rz+DY04LkCeSzCsbz3hh1zLg6BRQaewlvLZ
G8nsObubpKtAxZPPyF5kHiTIGjoxHd6k+G46ZubOylHcKnmWMWbF2t4J5ykROkxk
PwIDAQAB
-----END PUBLIC KEY-----"""

DEFAULT_RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA7vLVGzhmLSc7fMWhcJ7m7iKD2FuHP/mkEktQpDyYO5YY3nH8
lvTAsR8Yf0U41VZpN5O8Nk3Lw8WbOT9QuAHDPnp0ZbIMrvh6G/WmUMqTka/ekVWm
FWJoM8P7dK8eP39FRzBN3RZzS+bwgjpJdS1glQQ6Vfp60/uUMKQm29KsZ9sQIgYJ
OrVtYuzG+lITM0afRn+7K6gpXBC1nRruXXwBPxS6VJeU8XBXqTgflR6xwW3E2Rz+
...
-----END RSA PRIVATE KEY-----"""


def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, nonce

def aes_decrypt(ciphertext, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext

def des_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = message + " " * (8 - len(message) % 8)
    ciphertext = cipher.encrypt(padded_message.encode())
    return ciphertext

def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext).decode()
    return padded_message.strip()

def rsa_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext).decode()
    return plaintext


st.title("Multiple Encryption")
st.write("Hi, Sir Corton ")

col1, col2 = st.columns(2)

with col1:
    method = st.selectbox(
        "Method",
        ("Encrypt", "Decrypt"),
    )

with col2:
    encryption_type = st.selectbox(
        "Type",
        ("AES", "DES", "RSA"),
    )

if encryption_type == "AES":
    st.subheader(f"AES {method}")
    message = st.text_input("Enter the message:") if method == "Encrypt" else None
    key = st.text_input("Enter the 16-byte key (in hex):", value=DEFAULT_AES_KEY)
    nonce = st.text_input("Enter the nonce (in hex):", value="") if method == "Decrypt" else None
    ciphertext = st.text_input("Enter the ciphertext (in hex):", value="") if method == "Decrypt" else None

elif encryption_type == "DES":
    st.subheader(f"DES {method}")
    message = st.text_input("Enter the message:") if method == "Encrypt" else None
    key = st.text_input("Enter the 8-byte key (in hex):", value=DEFAULT_DES_KEY)
    ciphertext = st.text_input("Enter the ciphertext (in hex):", value="") if method == "Decrypt" else None

elif encryption_type == "RSA":
    st.subheader(f"RSA {method}")
    if method == "Encrypt":
        message = st.text_input("Enter the message:")
        public_key_input = st.text_area("Enter the public key:", value=DEFAULT_RSA_PUBLIC_KEY)
    elif method == "Decrypt":
        ciphertext = st.text_area("Enter the ciphertext (in hex):")
        private_key_input = st.text_area("Enter the private key:", value=DEFAULT_RSA_PRIVATE_KEY)

if st.button("Submit"):
    try:
        if method == "Encrypt":
            if encryption_type == "AES":
                key_bytes = bytes.fromhex(key)
                ciphertext, nonce = aes_encrypt(message, key_bytes)
                st.write(f"Ciphertext: {ciphertext.hex()}")
                st.write(f"Nonce: {nonce.hex()}")

            elif encryption_type == "DES":
                key_bytes = bytes.fromhex(key)
                ciphertext = des_encrypt(message, key_bytes)
                st.write(f"Ciphertext: {ciphertext.hex()}")

            elif encryption_type == "RSA":
                public_key = RSA.import_key(public_key_input)
                ciphertext = rsa_encrypt(message, public_key)
                st.write(f"Ciphertext: {ciphertext.hex()}")

        elif method == "Decrypt":
            if encryption_type == "AES":
                key_bytes = bytes.fromhex(key)
                nonce_bytes = bytes.fromhex(nonce)
                ciphertext_bytes = bytes.fromhex(ciphertext)
                plaintext = aes_decrypt(ciphertext_bytes, key_bytes, nonce_bytes)
                st.write(f"Plaintext: {plaintext}")

            elif encryption_type == "DES":
                key_bytes = bytes.fromhex(key)
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
