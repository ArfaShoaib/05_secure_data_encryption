import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate and store the encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Initialize state to store your encrypted data
if 'data_stored' not in st.session_state:
    st.session_state.data_stored = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

def hashed_key(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_text, hashed_passkey):
    for stored_hash, value in st.session_state.data_stored.items():
        if value["encrypted_text"] == encrypted_text and value["hashed_passkey"] == hashed_passkey:
            try:
                decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
                st.session_state.failed_attempts = 0  # Reset on successful decryption
                return decrypted_text
            except Exception:
                st.session_state.failed_attempts += 1
                # Limit failed attempts
                if st.session_state.failed_attempts >= 3:
                    st.error("Too many failed attempts. Please try again later.")
                return None
    return None  # Return None if decryption fails


# Streamlit UI
st.title("Secure Data Encryption")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("Store Data")
    user_input = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a unique passkey:", type="password")

    if st.button("Encrypt and Store"):
        if user_input and passkey:
            hashed_passkey = hashed_key(passkey)
            encrypted_text = encrypt_data(user_input)
            st.session_state.data_stored[hashed_passkey] = {
                "encrypted_text": encrypted_text,
                "hashed_passkey": hashed_passkey,
            }
            st.success("Data stored successfully!")
            
        else:
            st.error("Please enter both data and a passkey.")

elif choice == "Retrieve Data":
    st.subheader("Retrieve Data")
    encrypted_text_input = st.text_area("Enter Encrypted Data:")
    passkey_input = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text_input and passkey_input:
            hashed_passkey = hashed_key(passkey_input)
            decrypted_text = decrypt_data(encrypted_text_input, hashed_passkey)
            if decrypted_text:
                st.success(f"Decrypted Data: {decrypted_text}")
            else:
                st.error("Failed to decrypt data. Please check your passkey or the encrypted text.")
        else:
            st.error("Please enter both encrypted data and a passkey.")

elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials. Please try again.")