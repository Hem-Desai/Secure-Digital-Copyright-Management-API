import click
import getpass
import sys
from typing import Optional
from pathlib import Path
import os
from datetime import datetime, timedelta
from src.models.user import User, UserRole
from src.services.artifact_service import ArtifactService
from src.utils.logging import AuditLogger
from src.auth.rbac import RBACManager
from src.storage.db_storage import SQLiteStorage

class CLI:
    def __init__(self):
        self.artifact_service = ArtifactService()
        self.rbac_manager = RBACManager()
        self.logger = AuditLogger()
        self.db = SQLiteStorage()
        self.current_user: Optional[User] = None
        
    def login(self) -> bool:
        """Handle user login with rate limiting"""
        print("\nSecure Digital Copyright Management System")
        print("----------------------------------------")
        
        username = input("Username: ").strip()
        if not username:
            print("Username cannot be empty")
            return False
            
        # Check if user exists and isn't locked
        user_data = self.db.get_user_by_username(username)
        if not user_data:
            print("Invalid username or password")
            return False
            
        # Check for account lockout
        if user_data.get("account_locked"):
            print("Account is locked due to too many failed attempts.")
            print("Please contact your administrator.")
            return False
            
        # Check rate limiting
        last_attempt = user_data.get("last_login_attempt", 0)
        if datetime.utcnow().timestamp() - last_attempt < 30:  # 30 second delay between attempts
            print("Please wait before trying again")
            return False
            
        password = getpass.getpass("Password: ")
        if not password:
            print("Password cannot be empty")
            return False
            
        # Attempt authentication
        user = self.rbac_manager.authenticate(username, password)
        if user:
            self.current_user = user
            self.db.update_login_attempt(username, True)
            self.logger.log_auth_attempt(username, True, "127.0.0.1")
            print(f"\nWelcome {username}! You are logged in as: {user.role.value}")
            return True
            
        # Handle failed login
        self.db.update_login_attempt(username, False)
        self.logger.log_auth_attempt(username, False, "127.0.0.1")
        print("Invalid username or password")
        return False
        
    def require_auth(self):
        """Check if user is authenticated"""
        if not self.current_user:
            print("Please login first")
            sys.exit(1)
            
    def create_user(self, username: str, password: str, role: UserRole) -> bool:
        """Create a new user with secure password"""
        self.require_auth()
        if self.current_user.role != UserRole.ADMIN:
            print("Only administrators can create new users")
            return False
            
        user = self.rbac_manager.create_user(username, password, role)
        if not user:
            print("Failed to create user. Password must meet complexity requirements:")
            print("- Minimum 8 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter")
            print("- At least one number")
            print("- At least one special character")
            return False
            
        # Store user in database
        self.db.create({
            "table": "users",
            "id": user.id,
            "username": user.username,
            "password_hash": user.password_hash,
            "role": user.role.value,
            "created_at": user.created_at,
            "password_last_changed": datetime.utcnow().timestamp()
        })
        
        print(f"User {username} created successfully with role {role.value}")
        return True

@click.group()
@click.pass_context
def main(ctx):
    """Secure Digital Copyright Management System"""
    ctx.obj = CLI()

@main.command()
@click.pass_obj
def login(cli: CLI):
    """Login to the system"""
    if cli.login():
        print("Login successful")
    else:
        sys.exit(1)

@main.command()
@click.argument("username")
@click.argument("role", type=click.Choice(["admin", "owner", "viewer"]))
@click.pass_obj
def create_user(cli: CLI, username: str, role: str):
    """Create a new user (admin only)"""
    cli.require_auth()
    password = getpass.getpass("Enter password for new user: ")
    confirm = getpass.getpass("Confirm password: ")
    
    if password != confirm:
        print("Passwords do not match")
        sys.exit(1)
        
    role_enum = UserRole(role.lower())
    if not cli.create_user(username, password, role_enum):
        sys.exit(1)

@main.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--name', prompt=True)
@click.option('--type', 'content_type', prompt=True, 
              type=click.Choice(['lyrics', 'score', 'audio']))
@click.pass_obj
def upload(cli: CLI, file: str, name: str, content_type: str):
    """Upload a new artifact"""
    cli.require_auth()
    
    try:
        with open(file, 'rb') as f:
            content = f.read()
            
        artifact_id = cli.artifact_service.create_artifact(
            cli.current_user,
            name,
            content_type,
            content
        )
        
        if artifact_id:
            print(f"Artifact created with ID: {artifact_id}")
        else:
            print("Failed to create artifact")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

@main.command()
@click.argument('artifact_id')
@click.argument('output', type=click.Path())
@click.pass_obj
def download(cli: CLI, artifact_id: str, output: str):
    """Download an artifact"""
    cli.require_auth()
    
    try:
        content = cli.artifact_service.read_artifact(
            cli.current_user,
            artifact_id
        )
        
        if content:
            with open(output, 'wb') as f:
                f.write(content)
            print(f"Artifact saved to: {output}")
        else:
            print("Failed to read artifact")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

@main.command()
@click.pass_obj
def list(cli: CLI):
    """List available artifacts"""
    cli.require_auth()
    
    artifacts = cli.artifact_service.list_artifacts(cli.current_user)
    if not artifacts:
        print("No artifacts found")
        return
        
    for artifact in artifacts:
        print(f"\nID: {artifact['id']}")
        print(f"Name: {artifact['name']}")
        print(f"Type: {artifact['content_type']}")
        print(f"Created: {artifact['created_at']}")

@main.command()
@click.pass_obj
def whoami(cli: CLI):
    """Show current user information"""
    cli.require_auth()
    user = cli.current_user
    print(f"\nCurrent user information:")
    print(f"Username: {user.username}")
    print(f"Role: {user.role.value}")
    print(f"User ID: {user.id}")
    if user.role == UserRole.OWNER:
        artifacts = cli.db.get_user_artifacts(user.id)
        print(f"Owned artifacts: {len(artifacts)}")

if __name__ == "__main__":
    main() 