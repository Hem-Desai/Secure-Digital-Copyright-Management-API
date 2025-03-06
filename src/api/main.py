from fastapi import FastAPI, HTTPException, Depends, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import uvicorn
from datetime import datetime, timedelta
import os
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from ..auth.jwt_handler import JWTHandler
from ..auth.rbac import RBACManager, Permission
from ..models.user import User, UserRole
from ..services.artifact_service import ArtifactService
from ..services.encryption_service import EncryptionService
from ..utils.logging import AuditLogger

# Initialize FastAPI app
app = FastAPI(
    title="Digital Copyright Management API",
    description="REST API for managing digital content",
    version="1.0.0"
)

# Initialize services
jwt_handler = JWTHandler()
rbac_manager = RBACManager()
artifact_service = ArtifactService()
encryption_service = EncryptionService()
logger = AuditLogger()

# Initialize server logger
server_logger = logging.getLogger("uvicorn")

# Security scheme
security = HTTPBearer()

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1"]
)

# Request/Response Models
class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr]
    password: Optional[str]
    role: Optional[str]

class RecordCreate(BaseModel):
    name: str
    content: bytes
    content_type: str

class PostCreate(BaseModel):
    title: str
    content: str
    tags: List[str]

class PostUpdate(BaseModel):
    title: Optional[str]
    content: Optional[str]
    tags: Optional[List[str]]

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests"""
    start_time = datetime.now()
    path = request.url.path
    method = request.method
    
    # Log the incoming request
    logger.log_system(f"Incoming {method} request to {path}")
    
    response = await call_next(request)
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds() * 1000
    
    # Log the response
    logger.log_system(
        f"Completed {method} {path} - Status: {response.status_code} - Duration: {duration:.2f}ms"
    )
    
    # Detailed audit logging
    logger.log_event(
        event_type="api_request",
        user_id=getattr(request.state, "user_id", "anonymous"),
        details={
            "method": method,
            "path": path,
            "status_code": response.status_code,
            "duration_ms": duration,
            "client_ip": request.client.host
        }
    )
    return response

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> User:
    """Validate JWT token and return current user"""
    try:
        payload = jwt_handler.validate_token(credentials.credentials)
        if not payload:
            logger.log_error("auth_error", "Invalid token", {"token": "redacted"})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        user_data = rbac_manager.db.read(payload["user_id"], "users")
        if not user_data:
            logger.log_error("auth_error", "User not found", {"user_id": payload["user_id"]})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
            
        return User(
            id=user_data["id"],
            username=user_data["username"],
            email=user_data["email"],
            password_hash=user_data["password_hash"],
            role=UserRole(user_data["role"]),
            created_at=user_data["created_at"]
        )
    except Exception as e:
        logger.log_error("auth_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication"
        )

@app.put("/api/login")
@limiter.limit("100/hour")
async def login(request: Request, login_data: UserLogin):
    """Login endpoint that returns JWT token"""
    try:
        server_logger.info(f"Login attempt for user: {login_data.username}")
        
        user = rbac_manager.authenticate(
            username=login_data.username,
            password=login_data.password
        )
        
        if not user:
            logger.log_auth_attempt(
                login_data.username,
                False,
                request.client.host
            )
            server_logger.warning(f"Failed login attempt for user: {login_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        token = jwt_handler.generate_token(user.id, user.role.value)
        logger.log_auth_attempt(
            user.id,
            True,
            request.client.host
        )
        server_logger.info(f"Successful login for user: {login_data.username}")
        return {"access_token": token, "token_type": "bearer"}
        
    except Exception as e:
        error_msg = str(e)
        server_logger.error(f"Login error: {error_msg}")
        logger.log_error("login_error", error_msg)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/user")
@limiter.limit("200/day")
async def get_users(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Get all users (admin only)"""
    try:
        if current_user.role != UserRole.ADMIN:
            logger.log_error(
                "permission_denied",
                "Non-admin user attempted to list users",
                {"user_id": current_user.id}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
            
        users = rbac_manager.db.list("users")
        logger.log_event(
            "user_list",
            current_user.id,
            {"count": len(users)}
        )
        return {"users": users}
        
    except Exception as e:
        logger.log_error("user_list_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.put("/api/user")
@limiter.limit("200/day")
async def create_user(
    request: Request,
    user_data: UserCreate,
    current_user: User = Depends(get_current_user)
):
    """Create new user (admin only)"""
    try:
        if current_user.role != UserRole.ADMIN:
            logger.log_error(
                "permission_denied",
                "Non-admin user attempted to create user",
                {"user_id": current_user.id}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
            
        user = rbac_manager.create_user(
            username=user_data.username,
            password=user_data.password,
            role=UserRole(user_data.role)
        )
        
        if not user:
            logger.log_error(
                "user_creation_error",
                "Failed to create user",
                {"username": user_data.username}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid user data"
            )
            
        logger.log_event(
            "user_created",
            current_user.id,
            {
                "created_user_id": user.id,
                "username": user.username,
                "role": user.role.value
            }
        )
        return {"user_id": user.id}
        
    except Exception as e:
        logger.log_error("user_creation_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/user/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information"""
    try:
        user_data = rbac_manager.db.read(current_user.id, "users")
        if not user_data:
            logger.log_error(
                "user_not_found",
                "User data not found",
                {"user_id": current_user.id}
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        logger.log_event(
            "user_info_accessed",
            current_user.id,
            {"accessed_user_id": current_user.id}
        )
        return user_data
        
    except Exception as e:
        logger.log_error("user_info_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/artifacts")
@limiter.limit("200/day")
async def list_artifacts(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """List available artifacts"""
    try:
        artifacts = artifact_service.list_artifacts(current_user)
        logger.log_event(
            "artifacts_listed",
            current_user.id,
            {"count": len(artifacts)}
        )
        return {"artifacts": artifacts}
        
    except Exception as e:
        logger.log_error("artifact_list_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/api/artifacts")
@limiter.limit("200/day")
async def create_artifact(
    request: Request,
    artifact_data: RecordCreate,
    current_user: User = Depends(get_current_user)
):
    """Create new artifact"""
    try:
        artifact_id = artifact_service.create_artifact(
            user=current_user,
            name=artifact_data.name,
            content_type=artifact_data.content_type,
            content=artifact_data.content
        )
        
        if not artifact_id:
            logger.log_error(
                "artifact_creation_error",
                "Failed to create artifact",
                {"name": artifact_data.name}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to create artifact"
            )
            
        logger.log_event(
            "artifact_created",
            current_user.id,
            {
                "artifact_id": artifact_id,
                "name": artifact_data.name,
                "content_type": artifact_data.content_type,
                "size": len(artifact_data.content)
            }
        )
        return {"artifact_id": artifact_id}
        
    except Exception as e:
        logger.log_error("artifact_creation_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/artifacts/{artifact_id}")
@limiter.limit("200/day")
async def get_artifact(
    request: Request,
    artifact_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get artifact content"""
    try:
        content = artifact_service.read_artifact(current_user, artifact_id)
        if not content:
            logger.log_error(
                "artifact_not_found",
                "Artifact not found or access denied",
                {"artifact_id": artifact_id}
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Artifact not found"
            )
            
        logger.log_event(
            "artifact_downloaded",
            current_user.id,
            {"artifact_id": artifact_id}
        )
        return {"content": content}
        
    except Exception as e:
        logger.log_error("artifact_download_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.delete("/api/artifacts/{artifact_id}")
@limiter.limit("200/day")
async def delete_artifact(
    request: Request,
    artifact_id: str,
    current_user: User = Depends(get_current_user)
):
    """Delete artifact"""
    try:
        if artifact_service.delete_artifact(current_user, artifact_id):
            logger.log_event(
                "artifact_deleted",
                current_user.id,
                {"artifact_id": artifact_id}
            )
            return {"status": "success"}
            
        logger.log_error(
            "artifact_deletion_error",
            "Failed to delete artifact",
            {"artifact_id": artifact_id}
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found or permission denied"
        )
        
    except Exception as e:
        logger.log_error("artifact_deletion_error", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

if __name__ == "__main__":
    # Configure uvicorn logging
    log_config = uvicorn.config.LOGGING_CONFIG
    log_config["formatters"]["default"]["fmt"] = "\033[92m%(asctime)s\033[0m - \033[94m%(levelname)s\033[0m - %(message)s"
    log_config["formatters"]["access"]["fmt"] = "\033[92m%(asctime)s\033[0m - \033[94m%(levelname)s\033[0m - %(client_addr)s - %(request_line)s - %(status_code)s"
    
    # Configure logging handlers
    log_config["handlers"]["default"]["stream"] = "ext://sys.stdout"
    log_config["handlers"]["access"]["stream"] = "ext://sys.stdout"
    
    # Set log levels
    log_config["loggers"]["uvicorn"]["level"] = "INFO"
    log_config["loggers"]["uvicorn.access"]["level"] = "INFO"
    log_config["loggers"]["uvicorn.error"]["level"] = "INFO"
    
    print("\033[92m" + "=" * 50)
    print("Starting Digital Copyright Management API Server")
    print("=" * 50 + "\033[0m")
    
    # Run the API server
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=5000,
        ssl_keyfile="certs/key.pem",
        ssl_certfile="certs/cert.pem",
        reload=True,
        log_config=log_config,
        access_log=True
    ) 