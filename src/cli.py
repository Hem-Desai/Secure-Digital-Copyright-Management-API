import click
import getpass
import sys
import json
import shutil
from typing import Optional
from pathlib import Path
import os
from datetime import datetime, timedelta
from src.models.user import User, UserRole
from src.client.api_client import APIClient
from src.utils.logging import AuditLogger
from src.auth.rbac import RBACManager
from src.storage.db_storage import SQLiteStorage
from src.services.secure_enclave_service import SecureEnclaveService
from src.models.content_type import ContentType

# Constants
SESSION_FILE = ".session"
ARTIFACTS_DIR = "artifacts"  # Local directory to store artifacts

class CLI:
    def __init__(self):
        """Initialize CLI with API client"""
        self.api_client = APIClient()
        self.rbac_manager = RBACManager()
        self.logger = AuditLogger()
        self.secure_enclave = SecureEnclaveService()
        self.current_user: Optional[User] = None
        self._load_session()
        
        # Create artifacts directory if it doesn't exist
        if not os.path.exists(ARTIFACTS_DIR):
            os.makedirs(ARTIFACTS_DIR)
            
        # Create user-specific directories
        self._ensure_user_dirs()
        
    def _ensure_user_dirs(self):
        """Ensure user-specific directories exist"""
        if self.current_user:
            user_dir = os.path.join(ARTIFACTS_DIR, self.current_user.username)
            if not os.path.exists(user_dir):
                os.makedirs(user_dir)
                
    def _get_user_dir(self) -> str:
        """Get user's artifacts directory"""
        return os.path.join(ARTIFACTS_DIR, self.current_user.username)
        
    def _get_artifact_path(self, filename: str) -> str:
        """Get full path for an artifact"""
        return os.path.join(self._get_user_dir(), filename)
        
    def _load_session(self):
        """Load user session if exists"""
        try:
            if os.path.exists(SESSION_FILE):
                with open(SESSION_FILE, 'r') as f:
                    session_data = json.load(f)
                    if session_data.get("token"):
                        self.api_client.token = session_data["token"]
                        # Get user info using token
                        try:
                            user_info = self.api_client._make_request("GET", "/api/user/me")
                            if user_info:
                                self.current_user = User(
                                    id=user_info["id"],
                                    username=user_info["username"],
                                    email=user_info["email"],
                                    password_hash="",  # Not needed for session
                                    role=UserRole(user_info["role"]),
                                    created_at=user_info["created_at"]
                                )
                                self._ensure_user_dirs()  # Create user directory if needed
                        except Exception:
                            # If token is invalid, clear the session
                            self._clear_session()
        except Exception as e:
            print(f"Error loading session: {str(e)}")
            self._clear_session()
            
    def _save_session(self, token: str):
        """Save user session"""
        try:
            with open(SESSION_FILE, "w") as f:
                json.dump({"token": token}, f)
        except Exception as e:
            print(f"Error saving session: {str(e)}")
            
    def _clear_session(self):
        """Clear user session"""
        try:
            if os.path.exists(SESSION_FILE):
                os.remove(SESSION_FILE)
            self.api_client.token = None
            self.current_user = None
        except Exception as e:
            print(f"Error clearing session: {str(e)}")
            
    def login(self) -> bool:
        """Handle user login"""
        print("\nSecure Digital Copyright Management System")
        print("----------------------------------------")
        
        username = input("Username: ").strip()
        if not username:
            print("Username cannot be empty")
            return False
            
        try:
            password = getpass.getpass("Password: ")
        except:
            password = input("Password: ")
            
        if not password:
            print("Password cannot be empty")
            return False
            
        try:
            # Login through API
            response = self.api_client._make_request(
                "PUT",
                "/api/login",
                data={"username": username, "password": password}
            )
            
            if response and response.get("access_token"):
                self.api_client.token = response["access_token"]
                self._save_session(response["access_token"])
                
                # Get user info
                user_info = self.api_client._make_request("GET", "/api/user/me")
                if user_info:
                    self.current_user = User(
                        id=user_info["id"],
                        username=user_info["username"],
                        email=user_info["email"],
                        password_hash="",  # Not needed for session
                        role=UserRole(user_info["role"]),
                        created_at=user_info["created_at"]
                    )
                    self._ensure_user_dirs()  # Create user directory after login
                    print(f"\nWelcome {username}! You are logged in as: {self.current_user.role.value}")
                    return True
                    
            print("Invalid username or password")
            return False
            
        except Exception as e:
            print(f"Login failed: {str(e)}")
            return False
            
    def require_auth(self):
        """Check if user is authenticated"""
        if not self.current_user or not self.api_client.token:
            print("Please login first")
            sys.exit(1)
            
    def create_user(self, username: str, password: str, role: UserRole) -> bool:
        """Create a new user through API"""
        self.require_auth()
        
        try:
            response = self.api_client._make_request(
                "PUT",
                "/api/user",
                data={
                    "email": f"{username}@dcm.com",  # Generate email from username
                    "username": username,
                    "password": password,
                    "role": role.value
                }
            )
            
            if response and response.get("user_id"):
                print(f"User {username} created successfully with role {role.value}")
                return True
                
            print("Failed to create user. Please check requirements and try again.")
            return False
            
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            return False

    def logout(self) -> None:
        """Logout current user"""
        if self.current_user:
            self._clear_session()
            print("Logged out successfully")
        else:
            print("No user is currently logged in")

    def show_main_menu(self):
        """Show main menu"""
        while True:
            print("\nDigital Copyright Management System")
            print("==================================")
            print("1. Login")
            print("2. Exit")
            
            choice = input("\nEnter choice (1-2): ")
            
            if choice == "1":
                if self.login():
                    self.show_user_menu()
            elif choice == "2":
                print("Goodbye!")
                sys.exit(0)
            else:
                print("Invalid choice")
                
    def show_user_menu(self):
        """Show user menu based on role"""
        while True:
            print(f"\nWelcome {self.current_user.username}!")
            
            if self.current_user.role == UserRole.ADMIN:
                print("1. Upload artifact")
                print("2. Download artifact")
                print("3. List artifacts")
                print("4. Show my info")
                print("5. Create user")
                print("6. Delete artifact")
                print("7. Logout")
                print("8. Exit")
            elif self.current_user.role == UserRole.OWNER:
                print("1. Upload artifact")
                print("2. Download artifact")
                print("3. List artifacts")
                print("4. Show my info")
                print("5. Delete artifact")
                print("6. Logout")
                print("7. Exit")
            else:  # VIEWER
                print("1. List artifacts")
                print("2. Show my info")
                print("3. Logout")
                print("4. Exit")
            
            choice = input("\nEnter choice: ")
            
            if self.current_user.role == UserRole.ADMIN:
                if choice == "1":
                    self.upload_artifact()
                elif choice == "2":
                    self.download_artifact()
                elif choice == "3":
                    self.list_artifacts()
                elif choice == "4":
                    self.show_user_info()
                elif choice == "5":
                    self.create_user_menu()
                elif choice == "6":
                    self.delete_artifact()
                elif choice == "7":
                    self.logout()
                    return
                elif choice == "8":
                    print("Goodbye!")
                    sys.exit(0)
                else:
                    print("Invalid choice")
            elif self.current_user.role == UserRole.OWNER:
                if choice == "1":
                    self.upload_artifact()
                elif choice == "2":
                    self.download_artifact()
                elif choice == "3":
                    self.list_artifacts()
                elif choice == "4":
                    self.show_user_info()
                elif choice == "5":
                    self.delete_artifact()
                elif choice == "6":
                    self.logout()
                    return
                elif choice == "7":
                    print("Goodbye!")
                    sys.exit(0)
                else:
                    print("Invalid choice")
            else:  # VIEWER
                if choice == "1":
                    self.list_artifacts()
                elif choice == "2":
                    self.show_user_info()
                elif choice == "3":
                    self.logout()
                    return
                elif choice == "4":
                    print("Goodbye!")
                    sys.exit(0)
                else:
                    print("Invalid choice")

    def create_user_menu(self):
        """Handle user creation menu"""
        print("\nCreate New User")
        print("==============")
        
        username = input("Enter username: ")
        if not username:
            print("Username cannot be empty")
            return
            
        try:
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")
        except:
            password = input("Enter password: ")
            confirm = input("Confirm password: ")
            
        if not password or password != confirm:
            print("Passwords do not match or are empty")
            return
            
        print("\nSelect role:")
        print("1. Admin")
        print("2. Owner")
        print("3. Viewer")
        
        role_choice = input("Enter role (1-3): ")
        role_map = {
            "1": UserRole.ADMIN,
            "2": UserRole.OWNER,
            "3": UserRole.VIEWER
        }
        
        role = role_map.get(role_choice)
        if not role:
            print("Invalid role selected")
            return
            
        if self.create_user(username, password, role):
            print(f"User {username} created successfully!")
        else:
            print("Failed to create user. Please check requirements and try again.")

    def upload_artifact(self):
        """Handle artifact upload"""
        self.require_auth()
        
        print("\nUpload Artifact")
        print("==============")
        
        file_path = input("Enter file path: ").strip()
        if not os.path.exists(file_path):
            print("File not found")
            return
            
        name = input("Enter artifact name: ").strip()
        if not name:
            name = os.path.basename(file_path)
        
        print("\nSelect content type:")
        print("1. Audio (audio/mp3, audio/wav)")
        print("2. Video (video/mp4, video/avi)")
        print("3. Document (application/pdf)")
        print("4. Text (text/plain)")
        print("5. Other (application/octet-stream)")
        
        content_type_choice = input("\nEnter choice (1-5): ").strip()
        
        # Get file extension
        file_ext = os.path.splitext(file_path)[1].lower()
        
        # Map content types based on file extension
        content_type = "application/octet-stream"  # default
        if content_type_choice == "1":
            if file_ext == ".mp3":
                content_type = "audio/mp3"
            elif file_ext == ".wav":
                content_type = "audio/wav"
        elif content_type_choice == "2":
            if file_ext == ".mp4":
                content_type = "video/mp4"
            elif file_ext == ".avi":
                content_type = "video/avi"
        elif content_type_choice == "3":
            if file_ext == ".pdf":
                content_type = "application/pdf"
        elif content_type_choice == "4":
            if file_ext in [".txt", ".text"]:
                content_type = "text/plain"
            
        try:
            # Check file size before reading
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100MB in bytes
                print("File is too large. Maximum size is 100MB")
                return
                
            # Create destination path
            dest_path = self._get_artifact_path(name)
            
            # Copy file to artifacts directory
            shutil.copy2(file_path, dest_path)
            
            print(f"\nArtifact '{name}' uploaded successfully!")
            print(f"Stored in: {dest_path}")
                
        except Exception as e:
            print(f"Error uploading artifact: {str(e)}")
            return False
            
    def download_artifact(self):
        """Handle artifact download"""
        self.require_auth()
        
        print("\nDownload Artifact")
        print("================")
        
        # Show available artifacts
        self.list_artifacts()
        
        name = input("\nEnter artifact name: ").strip()
        source_path = self._get_artifact_path(name)
        
        if not os.path.exists(source_path):
            print(f"Artifact '{name}' not found")
            return
            
        output_path = input("Enter output path: ").strip()
        
        try:
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Copy file to destination
            shutil.copy2(source_path, output_path)
            print(f"Artifact downloaded successfully to {output_path}")
                
        except Exception as e:
            print(f"Error downloading artifact: {str(e)}")
            
    def list_artifacts(self):
        """List available artifacts"""
        self.require_auth()
        
        try:
            user_dir = self._get_user_dir()
            if not os.path.exists(user_dir):
                print("No artifacts found")
                return
                
            artifacts = os.listdir(user_dir)
            if not artifacts:
                print("No artifacts found")
                return
                
            print("\nYour Artifacts:")
            print("==============")
            print(f"{'Name':<30} {'Size':>10} {'Modified':>20}")
            print("-" * 60)
            
            for name in artifacts:
                path = self._get_artifact_path(name)
                size = os.path.getsize(path)
                modified = datetime.fromtimestamp(os.path.getmtime(path))
                print(f"{name:<30} {size:>10} {modified.strftime('%Y-%m-%d %H:%M:%S'):>20}")
                      
        except Exception as e:
            print(f"Error listing artifacts: {str(e)}")
            
    def delete_artifact(self):
        """Delete an artifact"""
        self.require_auth()
        
        print("\nDelete Artifact")
        print("==============")
        
        # Show available artifacts
        self.list_artifacts()
        
        name = input("\nEnter artifact name: ").strip()
        file_path = self._get_artifact_path(name)
        
        if not os.path.exists(file_path):
            print(f"Artifact '{name}' not found")
            return
            
        confirm = input("Are you sure you want to delete this artifact? (y/N): ")
        
        if confirm.lower() != 'y':
            print("Operation cancelled")
            return
            
        try:
            os.remove(file_path)
            print(f"Artifact '{name}' deleted successfully")
                
        except Exception as e:
            print(f"Error deleting artifact: {str(e)}")
            
    def show_user_info(self):
        """Show current user information"""
        self.require_auth()
        
        try:
            user_info = self.api_client._make_request("GET", "/api/user/me")
            if user_info:
                print("\nUser Information:")
                print("================")
                print(f"Username: {user_info['username']}")
                print(f"Email: {user_info['email']}")
                print(f"Role: {user_info['role']}")
                print(f"Created: {datetime.fromtimestamp(user_info['created_at'])}")
            else:
                print("Failed to get user information")
                
        except Exception as e:
            print(f"Error getting user information: {str(e)}")

@click.group()
@click.pass_context
def main(ctx):
    """Secure Digital Copyright Management CLI"""
    ctx.obj = CLI()

@main.command()
def start():
    """Start the CLI application"""
    cli = CLI()
    cli.show_main_menu()

if __name__ == "__main__":
    main() 