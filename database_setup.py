import sqlite3
import bcrypt
import uuid
import pyotp
import streamlit as st
import os

class DatabaseManager:
    def __init__(self, db_path='/data/secure_file_sharing.db'):
        """Initialize database connection with Railway-compatible paths"""
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        self.create_tables()

    def create_tables(self):
        """Create tables with proper constraints and indexes"""
        cursor = self.conn.cursor()
        
        # Users table with additional constraints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                totp_secret TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Files table with improved indexing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                encrypted_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER,
                file_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY(recipient_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_recipient ON files(recipient_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_sender ON files(sender_id)')
        
        self.conn.commit()

    def register_user(self, username, password, email):
        """Register new user with password hashing and TOTP secret"""
        try:
            user_id = str(uuid.uuid4())
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            totp_secret = pyotp.random_base32()
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO users (user_id, username, password_hash, email, totp_secret) 
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username.strip(), password_hash, email.strip(), totp_secret))
            
            self.conn.commit()
            return user_id, totp_secret
        except sqlite3.IntegrityError as e:
            st.error(f"Registration error: {str(e)}")
            return None, None

    def authenticate_user(self, username, password, otp):
        """Authenticate user with password and TOTP verification"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT user_id, password_hash, totp_secret FROM users 
                WHERE username = ? AND is_active = TRUE
            ''', (username.strip(),))
            
            user = cursor.fetchone()
            if not user:
                return None

            user_id, password_hash, totp_secret = user
            
            if bcrypt.checkpw(password.encode('utf-8'), password_hash):
                if pyotp.TOTP(totp_secret).verify(otp):
                    # Update last login time
                    cursor.execute('''
                        UPDATE users SET last_login = CURRENT_TIMESTAMP 
                        WHERE user_id = ?
                    ''', (user_id,))
                    self.conn.commit()
                    return user_id
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
        return None

    def get_user_id_by_username(self, username):
        """Get user ID by username (case-insensitive)"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT user_id FROM users 
                WHERE username = ? COLLATE NOCASE
            ''', (username.strip(),))
            result = cursor.fetchone()
            return result[0] if result else None
        except Exception as e:
            st.error(f"User lookup error: {str(e)}")
            return None

    def add_file_record(self, filename, sender_id, recipient_id, encrypted_path, file_hash):
        """Add file transfer record to database"""
        try:
            file_id = str(uuid.uuid4())
            file_size = os.path.getsize(encrypted_path) if os.path.exists(encrypted_path) else 0
            file_type = os.path.splitext(filename)[1].lower()
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO files (
                    file_id, filename, sender_id, recipient_id, 
                    encrypted_path, file_hash, file_size, file_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_id, filename, sender_id, recipient_id,
                encrypted_path, file_hash, file_size, file_type
            ))
            
            self.conn.commit()
            return file_id
        except Exception as e:
            st.error(f"Failed to save file record: {str(e)}")
            return None

    def get_received_files(self, recipient_id):
        """Get all files received by a user"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT 
                    f.file_id, 
                    f.filename, 
                    u.username as sender_name, 
                    f.encrypted_path, 
                    f.timestamp,
                    f.file_size,
                    f.file_type
                FROM files f
                JOIN users u ON f.sender_id = u.user_id
                WHERE f.recipient_id = ?
                ORDER BY f.timestamp DESC
            ''', (recipient_id,))
            
            return cursor.fetchall()
        except Exception as e:
            st.error(f"Failed to fetch received files: {str(e)}")
            return []

    def __del__(self):
        """Clean up database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()