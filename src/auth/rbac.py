from enum import Enum
from typing import Dict, List, Optional, Tuple
from ..models.user import User, UserRole
import hashlib
import os

class Permission(Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"

class RBACManager:
    def __init__(self):
        # Define permission matrix for each role
        self._permissions: Dict[UserRole, List[Permission]] = {
            UserRole.ADMIN: [
                Permission.CREATE, Permission.READ,
                Permission.UPDATE, Permission.DELETE,
                Permission.LIST
            ],
            UserRole.OWNER: [
                Permission.READ, Permission.UPDATE,
                Permission.DELETE, Permission.LIST
            ],
            UserRole.VIEWER: [Permission.READ, Permission.LIST]
        }
        
        # In production, this would be in a database
        self._users = {
            "admin": User(
                id="admin",
                username="admin",
                password_hash=self._hash_password("admin"),
                role=UserRole.ADMIN,
                created_at=0,
                artifacts=[]
            )
        }
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials"""
        user = self._users.get(username)
        if user and user.password_hash == self._hash_password(password):
            return user
        return None
    
    def check_permission(self, user: User, permission: Permission, 
                        resource_id: Optional[str] = None) -> bool:
        """
        Check if user has the required permission
        If resource_id is provided, also check ownership for OWNER role
        """
        if user.role == UserRole.ADMIN:
            return True
            
        if permission not in self._permissions[user.role]:
            return False
            
        # For OWNER role, check resource ownership
        if (user.role == UserRole.OWNER and 
            resource_id is not None and 
            resource_id not in user.artifacts):
            return False
            
        return True 