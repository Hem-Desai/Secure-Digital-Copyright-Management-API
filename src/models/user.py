from enum import Enum
from dataclasses import dataclass
from typing import List, Optional

class UserRole(Enum):
    ADMIN = "admin"
    OWNER = "owner"
    VIEWER = "viewer"

@dataclass
class User:
    id: str
    username: str
    email: str  # Added email field
    password_hash: str  # Store as string since we decode after hashing
    role: UserRole
    created_at: float
    artifacts: Optional[List[str]] = None  # List of artifact IDs owned by user
    failed_login_attempts: int = 0  # Track failed login attempts
    last_login_attempt: float = 0  # Track time of last login attempt
    
    def __post_init__(self):
        """Initialize optional fields"""
        if self.artifacts is None:
            self.artifacts = []
    
    def has_permission(self, action: str, resource: str) -> bool:
        """
        Check if user has permission to perform action on resource
        """
        if self.role == UserRole.ADMIN:
            return True
            
        if self.role == UserRole.OWNER:
            return action in ['read', 'update', 'delete', 'create', 'upload']
            
        if self.role == UserRole.VIEWER:
            return action == 'read'
            
        return False 