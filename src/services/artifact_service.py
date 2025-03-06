import uuid
import os
from datetime import datetime
from typing import Optional, Dict, List, BinaryIO, Any
import hashlib

from ..models.artifact import Artifact
from ..models.user import User, UserRole
from ..storage.db_storage import SQLiteStorage
from ..storage.file_storage import FileStorage
from ..encryption.aes_handler import AESHandler
from ..utils.checksum import generate_checksum
from ..utils.logging import AuditLogger
from ..auth.rbac import RBACManager, Permission
from ..services.secure_enclave_service import SecureEnclaveService

class ArtifactService:
    def __init__(self):
        """Initialize artifact service"""
        self.db = SQLiteStorage()
        self.rbac = RBACManager()
        self.secure_enclave = SecureEnclaveService()
        
    def create_artifact(self, user: User, name: str, content_type: str, content: bytes) -> Optional[str]:
        """Create a new artifact"""
        try:
            # Check permission
            if not self.rbac.check_permission(user, Permission.UPLOAD):
                return None
                
            # Generate artifact ID
            artifact_id = str(uuid.uuid4())
            
            # Calculate file size and checksum
            file_size = len(content)
            checksum = hashlib.sha256(content).hexdigest()
            
            # Create artifact record
            artifact_data = {
                "table": "artifacts",
                "id": artifact_id,
                "name": name,
                "content_type": content_type,
                "owner_id": user.id,
                "file_size": file_size,
                "created_at": datetime.now().timestamp(),
                "encryption_key_id": "",  # Will be set by secure_enclave
                "checksum": checksum
            }
            
            # Handle upload through secure enclave
            if self.secure_enclave.handle_upload_request(
                user=user,
                file_path=None,  # Not using file path since we have content directly
                name=name,
                content_type=content_type,
                file_size=file_size,
                content=content,
                artifact_id=artifact_id
            ):
                # Add to database
                if self.db.create(artifact_data):
                    # Add to owner's artifacts if user is owner
                    if user.role == UserRole.OWNER:
                        self.rbac.add_artifact_to_owner(user.id, artifact_id)
                        if not hasattr(user, 'artifacts'):
                            user.artifacts = []
                        user.artifacts.append(artifact_id)
                    return artifact_id
                    
            return None
            
        except Exception as e:
            print(f"Artifact creation error: {str(e)}")
            return None
            
    def read_artifact(self, user: User, artifact_id: str) -> Optional[bytes]:
        """Read an artifact's content"""
        try:
            # Check permission
            if not self.rbac.check_permission(user, Permission.READ, artifact_id):
                return None
                
            # Get artifact through secure enclave
            return self.secure_enclave.handle_download_request(user, artifact_id)
            
        except Exception as e:
            print(f"Error reading artifact: {str(e)}")
            return None
            
    def update_artifact(self, user: User, artifact_id: str, content: bytes) -> bool:
        """Update an artifact's content"""
        try:
            # Check permission
            if not self.rbac.check_permission(user, Permission.UPDATE, artifact_id):
                return False
                
            # Calculate new file size and checksum
            file_size = len(content)
            checksum = hashlib.sha256(content).hexdigest()
            
            # Get current artifact
            artifact = self.db.read(artifact_id, "artifacts")
            if not artifact:
                return False
                
            # Update through secure enclave
            if self.secure_enclave.handle_update_request(
                user=user,
                artifact_id=artifact_id,
                content=content,
                file_size=file_size,
                checksum=checksum
            ):
                # Update database record
                update_data = {
                    "table": "artifacts",
                    "id": artifact_id,
                    "file_size": file_size,
                    "checksum": checksum
                }
                return self.db.update(update_data)
                
            return False
            
        except Exception as e:
            print(f"Error updating artifact: {str(e)}")
            return False
            
    def delete_artifact(self, user: User, artifact_id: str) -> bool:
        """Delete an artifact"""
        try:
            # Check permission
            if not self.rbac.check_permission(user, Permission.DELETE, artifact_id):
                return False
                
            # Delete through secure enclave
            if self.secure_enclave.delete_artifact(user, artifact_id):
                # Remove from database
                if self.db.delete(artifact_id, "artifacts"):
                    # Remove from owner's artifacts if exists
                    if user.role == UserRole.OWNER and hasattr(user, 'artifacts'):
                        if artifact_id in user.artifacts:
                            user.artifacts.remove(artifact_id)
                    return True
                    
            return False
            
        except Exception as e:
            print(f"Error deleting artifact: {str(e)}")
            return False
            
    def list_artifacts(self, user: User) -> List[Dict[str, Any]]:
        """List available artifacts"""
        try:
            # Check permission
            if not self.rbac.check_permission(user, Permission.LIST):
                return []
                
            # Get all artifacts
            artifacts = self.db.list("artifacts")
            
            # Filter based on role
            if user.role == UserRole.OWNER:
                artifacts = [a for a in artifacts if a["owner_id"] == user.id]
            elif user.role == UserRole.VIEWER:
                # Remove sensitive fields for viewers
                for artifact in artifacts:
                    artifact.pop("encryption_key_id", None)
                    artifact.pop("checksum", None)
                    
            return artifacts
            
        except Exception as e:
            print(f"Error listing artifacts: {str(e)}")
            return []
            
    def create_post(self, user: User, title: str, content: str, tags: List[str]) -> Optional[str]:
        """Create a new post"""
        try:
            # Check permission
            if not self.rbac.check_permission(user, Permission.CREATE):
                return None
                
            # Create post
            post_data = {
                "title": title,
                "content": content,
                "author_id": user.id,
                "tags": tags
            }
            
            return self.db.create_post(post_data)
            
        except Exception as e:
            print(f"Error creating post: {str(e)}")
            return None
            
    def get_post(self, user: User, post_id: str) -> Optional[Dict[str, Any]]:
        """Get a post by ID"""
        try:
            # Get post
            post = self.db.get_post(post_id)
            if not post:
                return None
                
            # Check permission
            if not self.rbac.check_permission(user, Permission.READ, post_id):
                return None
                
            return post
            
        except Exception as e:
            print(f"Error getting post: {str(e)}")
            return None
            
    def list_posts(self, user: User) -> List[Dict[str, Any]]:
        """List all posts (admin only)"""
        try:
            if user.role != UserRole.ADMIN:
                return []
                
            return self.db.list_posts()
            
        except Exception as e:
            print(f"Error listing posts: {str(e)}")
            return []
            
    def list_user_posts(self, user: User) -> List[Dict[str, Any]]:
        """List posts owned by user"""
        try:
            return self.db.list_posts({"author_id": user.id})
            
        except Exception as e:
            print(f"Error listing user posts: {str(e)}")
            return []
            
    def list_public_posts(self) -> List[Dict[str, Any]]:
        """List public posts (accessible by viewers)"""
        try:
            return self.db.list_posts()
            
        except Exception as e:
            print(f"Error listing public posts: {str(e)}")
            return []
            
    def update_post(self, user: User, post_id: str, post_data: Dict[str, Any]) -> bool:
        """Update a post"""
        try:
            # Get post
            post = self.db.get_post(post_id)
            if not post:
                return False
                
            # Check permission
            if not self.rbac.check_permission(user, Permission.UPDATE, post_id):
                return False
                
            # Only allow author or admin to update
            if user.role != UserRole.ADMIN and post["author_id"] != user.id:
                return False
                
            return self.db.update_post(post_id, post_data)
            
        except Exception as e:
            print(f"Error updating post: {str(e)}")
            return False
            
    def delete_post(self, user: User, post_id: str) -> bool:
        """Delete a post"""
        try:
            # Get post
            post = self.db.get_post(post_id)
            if not post:
                return False
                
            # Check permission
            if not self.rbac.check_permission(user, Permission.DELETE, post_id):
                return False
                
            # Only allow author or admin to delete
            if user.role != UserRole.ADMIN and post["author_id"] != user.id:
                return False
                
            return self.db.delete_post(post_id)
            
        except Exception as e:
            print(f"Error deleting post: {str(e)}")
            return False 