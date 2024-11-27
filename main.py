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
MIIEogIBAAKCAQEAisLz5t2ARC1axLH3fNIlsI1U7Lw0NCkFkD0n/wY97auIuo8n
XetJ75xEWLDKCQfxQ2T+Y5ByozZuAiFsTaFgokqs4RP8a7XAURAsx5FpthPe28M1
IE3gzh1I6De5OmxBwnks4edSQOCfkdEDC3I3C0URidTfCJg24CMQoGiS+NY9bueB
zNN54uVb0opPHJWIkukzRKPoYgmyVh8EHeAL4AA8K/ZKuFpdoFAhn6a5w5hQh/Dd
8kLhYTiAiElGIRUWF2mknzl7kWwbAaMkLCSegxryHoha//PPAWjnR1H5l2PtkW8+
37sDRC879WLrb3KYetbpAYcdHZm3i0VDPN33rQIDAQABAoIBADb6DaNa//5DD/Ld
ZeY05ozgOhT/bhl6ZUNkD4wpf3DCZQ4xOJIr7iO6gJO5G5rfZDXk9ishaGIE5yn9
7wiE1yIFvyAACKLuJC+Z3nwFP2JN1h6w5UQSxu4yyReEOGWOzbEMzH0GZt7ggChI
LNIkou1apJu81M71a8x66BP9yrk+pyuWAhB5JNBf8v00cBfwMjbuIk4gKFh5uUXZ
/2mTMXHLLG3sUgSBofmBDONyjzbtPR779Rjz5S2GoJ+ZRauiz5davJucki643UH8
OgepvoKiujRMWxXlWyR9DTEdsbJNbZdYZ7OVTOe+o3uj59gT3yU9X0xFX7O8cBk2
Q97zlNsCgYEAtVUKZv0htra8LskhtrFgduZUSw7fB8QAfrOMwQh0UPH/+FrMV8rE
81OQUAIXPc/B2RnJSaFn1YaxJNVnrFfhfKpg3emDgLQLRQ0QFrzqDvxWyB1/8JmQ
tvm3itpa+ulTKm97MuA7w+ydnKVqRtJkUWkXUxoe6ix84UE1a+i/B38CgYEAw+Zd
/PUtWZrDm3+EnMXZquAln6Dy/UWaU8P7S3khlCTCENL5ul4JX/TD5YvCmQmRZvBC
4Pek+NdDJ8wpTymL08+I4Kz0P3tuZHUTLtay4Eof6679F+uG2507GkdDpHQDWEkP
XIYBsK7zaK367PNs7JC8NBbLM2YzFghgRZ8qNtMCgYBti7qFDVdYsnxtJ0UewXmt
WuiBj7JdVqOV55KY6yqZ3BjvSKs6Pl1NQqZkL18rEF/jcBiSStgXvw81WVcQXuby
EVwDtBaloh9Mz99wXSBpfThQHMI18A/k+mdPkypzepGriT28NorkigWNpMDXmDLS
m9JjedxDTC0FSAel8S22sQKBgAUDRxJq/68US78V40HTuj8qHyxXhQBAILPWBv8m
aVqOGj0t+N/w+hJvg/fCvMcHvKXCriNtktYfRAOnsMLq0D4qSFlfc5yQPwHpEQWY
ztj4bJquTqGnEDtcaZ/BhRSXN2Kx8+etMivgPjBGi242yGnBRl+a2bZF/japHjWJ
3h2rAoGAE2EwXx+ZOWVL2whPgha55YrVAxUyB757GQydwb6UzIQxzaSlPSzM7F9j
W6LgOgFbbnoffZMTREtRmxtFdA8/W0VdAXniz40xwwJz3rJWGihPvVwCuwxQk5Gb
U4+N8yOHwCFTA9prJygoe0s5dtA1X+z4NMyt8t8uYhcBjDQfrrw=
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

def rsa_decrypt(ciphertext, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
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
