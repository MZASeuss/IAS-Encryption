import streamlit as st
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA

DEFAULT_AES_KEY = "00112233445566778899aabbccddeeff"
DEFAULT_DES_KEY = "0123456789abcdef"

DEFAULT_RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvULwfzwDGNIJNd0jdiSm
fYitIn3oAwzueI+LUlP3xxfq826dS4E+dwgsFkS2fuogh4OAnuWxjCD09l/x7NCR
gEpizE03CIEzG+uY3s+8MRR1toqpCYtymUZrAobDCvmIwfI5n56/Su/UVwAB98oS
7ot2L+yGdTiZrqPsGe9ibcOeKLJfXF32WeZgOAK1aAi2EMU5zHcvegNYp9esZb1v
MJDwunXJKbV2f1Uzk/0VNyGx7e8imRqw1y8afcqJ1qzDgKXu+0H+t9FFr5VwtKYQ
5dKYpa8JWk0GiNdBnwE/E8WIgGrAmiNNNlMALDuvLA2B1abDCy7lnmEXIPHjOjrK
UQIDAQAB
-----END PUBLIC KEY-----"""

DEFAULT_RSA_PRIVATE_KEY ="""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvULwfzwDGNIJNd0jdiSmfYitIn3oAwzueI+LUlP3xxfq826d
S4E+dwgsFkS2fuogh4OAnuWxjCD09l/x7NCRgEpizE03CIEzG+uY3s+8MRR1toqp
CYtymUZrAobDCvmIwfI5n56/Su/UVwAB98oS7ot2L+yGdTiZrqPsGe9ibcOeKLJf
XF32WeZgOAK1aAi2EMU5zHcvegNYp9esZb1vMJDwunXJKbV2f1Uzk/0VNyGx7e8i
mRqw1y8afcqJ1qzDgKXu+0H+t9FFr5VwtKYQ5dKYpa8JWk0GiNdBnwE/E8WIgGrA
miNNNlMALDuvLA2B1abDCy7lnmEXIPHjOjrKUQIDAQABAoIBAAW/+GAtMqBxzgMN
Tl3Gjg1x9iyasvkQwK1NjAKJBfl4w7eGXmWOypb6aRTsVZtCeq2FENwC+Ti+zgX1
8wkGwAQBRaWw/NpQdaenxlOvDBmR2Cs7SDUVFTPTrnbtdmnUHClAtirnO1/H855B
sk2b8vpLUZmAIbMtqTNjr6MbL431+qQS7QPj+mOjiY9HD9iolHWyRuZFP7clnVsk
LERnYmz5sO9R2f09ttLQm1WBFBUBkalCxFX4V/m1oIAthQ1WI8ab6hnVzWIIH5Id
aFxsJga67bstnESnEsFQpRvr2O5MZju1PeTLTL6SXy6J00FHQYzGXzvLpZSOafUj
P+TBE7cCgYEAx5tmQqir2lUZgYOEs2Wpq8ws6+VvUzUgNvQmsnOjYUBjkZJ2p9WJ
ZCLv5gCxTsSqyf7UhN+vZqilYY4by/8CAJ/2pN7Z/SX4EnPnkb4oychEBxHZOt0n
VwGTCY5Xu8gjhjNBe9Nb88iIkHsXp2Qal/zO5+YcUbTm7mjxY9ChO6MCgYEA8rtM
EnQuOETPvpecivLzpLGhv9encCh1UjEZJe4PjCjkcgxYQAZfVhZwPcg3Q3YPN6Ep
Obvf6hCsignjSO+twtwnKnTg2lcIHei3IaadToRYGcZSPQeQdvvpQTpu5tRYHf0G
xqsYjcStoaenY6J0HE8K0EI5d10aQwF2jAbSgXsCgYB9RfdxAIESvvQKB6vCF5zc
GIFc75rlwuLb+nFK8C5qu8mBtEVJ4kefFBox5N9iyyVRLuDcH7LqoA9jYZfqeLoe
AEcAhGiVaz38/scn/guFUG35bedC/UdSYMeSaMaBMQOylvqTJzx/jKzA2LAouzfB
icWlXxMI6JtCp5RQC8EVNwKBgQDbGg/n1HFoH0z6uHX4wqcE8caUmcAtMIf+Qg12
PHZSSRM0k0oRuO7TkXuNeS3ROj8wMsw4rgrHiHeGPrinvJm3e+vqmgfhbpAIF2k+
+dui5Tl1Qpw3NJ3FmUyKsYkr2V8U6rH0ILsQNQmaEvC4sgpnBz42kKC4yxSKiUaN
zRa1AwKBgQCNXy4lSCPF97Jal8m5ew+xTkOlgIDXWG7oHXFl04W4/H1RQY2dcAo3
y+MBdUSeydrBGoJgTIX14RiSvAVFLyKkuFhX5dVrf/fBTcGmEUaEwwz+0yVQ0lMi
HpWmxgCgtT4PqVl2XL3JgoocrGRo+HKzu0oA88vkzW8a0FPTFS5mBQ==
-----END RSA PRIVATE KEY-----"""

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
