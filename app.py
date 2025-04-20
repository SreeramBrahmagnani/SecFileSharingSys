import streamlit as st
import os
from database_setup import DatabaseManager
from file_encryption import FileEncryptor

class SecureFileSharing:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.setup_page()
        self.ensure_data_dirs()

    def ensure_data_dirs(self):
        """Create required directories in /data for Railway persistence"""
        os.makedirs("/data/temp", exist_ok=True)
        os.makedirs("/data/encrypted_files", exist_ok=True)
        os.makedirs("/data/decrypted_files", exist_ok=True)

    def setup_page(self):
        st.set_page_config(page_title="Secure File Sharing", page_icon="🔒")
        st.title("Secure File Sharing System")

    def registration_page(self):
        st.subheader("User Registration")
        username = st.text_input("Username", key="reg_username")
        email = st.text_input("Email", key="reg_email")
        password = st.text_input("Password", type="password", key="reg_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password")

        if st.button("Register"):
            if password != confirm_password:
                st.error("Passwords do not match")
                return

            user_id, totp_secret = self.db_manager.register_user(username, password, email)
            if user_id:
                st.success("Registration Successful!")
                st.info(f"Your TOTP Secret: {totp_secret}")
                st.warning("Please save this secret for future authentication")
            else:
                st.error("Registration Failed. Username or email might already exist.")

    def login_page(self):
        st.subheader("Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        otp = st.text_input("One-Time Password", key="login_otp")

        if st.button("Login"):
            user_id = self.db_manager.authenticate_user(username, password, otp)
            if user_id:
                st.session_state['user_id'] = user_id
                st.session_state['username'] = username
                st.rerun()
            else:
                st.error("Invalid Credentials")

    def file_sharing_page(self):
        st.subheader("Secure File Sharing")
        
        # File Upload Section
        uploaded_file = st.file_uploader("Choose a file", type=['txt', 'pdf', 'docx', 'xlsx'], key="file_uploader")
        recipient_username = st.text_input("Recipient Username", key="recipient_username")

        if st.button("Share File") and uploaded_file:
            recipient_id = self.db_manager.get_user_id_by_username(recipient_username)
            if not recipient_id:
                st.error(f"User {recipient_username} not found")
                return

            # Use Railway-compatible temp path
            temp_path = os.path.join("/data/temp", uploaded_file.name)
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            try:
                encrypted_path, file_hash, salt = FileEncryptor.encrypt_file(
                    temp_path, st.session_state['user_id']
                )
                self.db_manager.add_file_record(
                    uploaded_file.name, st.session_state['user_id'], recipient_id, encrypted_path, file_hash
                )
                st.success(f"File encrypted and shared with {recipient_username}")
            except Exception as e:
                st.error(f"File sharing failed: {str(e)}")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        # Received Files Section
        st.subheader("Received Files")
        received_files = self.db_manager.get_received_files(st.session_state['user_id'])
        if received_files:
            for file_id, filename, sender, encrypted_path, timestamp in received_files:
                col1, col2, col3 = st.columns([3, 2, 1])
                with col1:
                    st.write(f"Filename: {filename}")
                with col2:
                    st.write(f"From: {sender}")
                with col3:
                    if st.button(f"Decrypt {file_id}", key=f"decrypt_{file_id}"):
                        try:
                            decrypted_path = FileEncryptor.decrypt_file(
                                encrypted_path, st.session_state['user_id'], filename
                            )
                            with open(decrypted_path, 'rb') as f:
                                st.download_button(
                                    "Download Decrypted File", 
                                    f.read(), 
                                    os.path.basename(decrypted_path),
                                    key=f"download_{file_id}"
                                )
                            os.remove(decrypted_path)
                            st.success("File decrypted successfully!")
                        except Exception as e:
                            st.error(f"Decryption failed: {str(e)}")
        else:
            st.info("No files received yet.")

    def logout(self):
        if 'user_id' in st.session_state:
            del st.session_state['user_id']
            del st.session_state['username']

    def main(self):
        if 'user_id' not in st.session_state:
            tab1, tab2 = st.tabs(["Login", "Register"])
            with tab1:
                self.login_page()
            with tab2:
                self.registration_page()
        else:
            st.sidebar.write(f"Logged in as: {st.session_state['username']}")
            if st.sidebar.button("Logout"):
                self.logout()
                st.rerun()
            self.file_sharing_page()

def main():
    app = SecureFileSharing()
    app.main()

if __name__ == "__main__":
    main()