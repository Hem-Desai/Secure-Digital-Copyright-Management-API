import requests
from typing import Optional, Dict, Any, List
import os
from urllib.parse import urljoin
import json
from ..utils.logging import AuditLogger
import urllib3

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIClient:
    def __init__(self, base_url: str = "https://localhost:5000"):
        """Initialize API client with base URL"""
        self.base_url = base_url
        self.token: Optional[str] = None
        self.logger = AuditLogger()
        
        # Verify SSL certificate in production
        self.verify_ssl = not base_url.startswith("https://localhost")
        
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authorization if token exists"""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
        
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        files: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to API endpoint"""
        try:
            url = urljoin(self.base_url, endpoint)
            headers = self._get_headers()
            
            # Remove content-type header if uploading files
            if files:
                headers.pop("Content-Type", None)
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data if not files else None,
                files=files,
                verify=self.verify_ssl
            )
            
            # Handle response
            if response.status_code == 401:
                raise Exception("Authentication required")
            if response.status_code == 422:
                error_detail = response.json().get("detail", "Validation error")
                raise Exception(f"Validation error: {error_detail}")
            if response.status_code == 413:
                raise Exception("File too large")
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.log_error("api_request_error", str(e))
            raise
            
    def login(self, username: str, password: str) -> bool:
        """Login user and store JWT token"""
        try:
            response = self._make_request(
                method="PUT",
                endpoint="/api/login",
                data={"username": username, "password": password}
            )
            self.token = response.get("access_token")
            return bool(self.token)
            
        except Exception as e:
            self.logger.log_error("login_error", str(e))
            return False
            
    def create_user(self, username: str, password: str, role: str) -> Optional[str]:
        """Create a new user"""
        try:
            response = self._make_request(
                method="POST",
                endpoint="/api/users",
                data={
                    "username": username,
                    "password": password,
                    "role": role
                }
            )
            return response.get("user_id")
            
        except Exception as e:
            self.logger.log_error("user_creation_error", str(e))
            return None
            
    def create_artifact(
        self,
        name: str,
        content_type: str,
        content: bytes
    ) -> Optional[str]:
        """Create a new artifact"""
        try:
            # Create multipart form-data
            files = {
                'file': (name, content, content_type)
            }
            data = {
                'name': name,
                'content_type': content_type
            }
            
            response = self._make_request(
                method="POST",
                endpoint="/api/artifacts",
                data=data,
                files=files
            )
            
            return response.get("artifact_id")
            
        except Exception as e:
            self.logger.log_error("artifact_creation_error", str(e))
            return None
            
    def read_artifact(self, artifact_id: str) -> Optional[bytes]:
        """Read an artifact's content"""
        try:
            response = self._make_request(
                method="GET",
                endpoint=f"/api/artifacts/{artifact_id}"
            )
            content_hex = response.get("content")
            return bytes.fromhex(content_hex) if content_hex else None
            
        except Exception as e:
            self.logger.log_error("artifact_read_error", str(e))
            return None
            
    def delete_artifact(self, artifact_id: str) -> bool:
        """Delete an artifact"""
        try:
            self._make_request(
                method="DELETE",
                endpoint=f"/api/artifacts/{artifact_id}"
            )
            return True
            
        except Exception as e:
            self.logger.log_error("artifact_deletion_error", str(e))
            return False
            
    def list_artifacts(self) -> List[Dict[str, Any]]:
        """List available artifacts"""
        try:
            response = self._make_request(
                method="GET",
                endpoint="/api/artifacts"
            )
            return response.get("artifacts", [])
            
        except Exception as e:
            self.logger.log_error("artifact_list_error", str(e))
            return [] 