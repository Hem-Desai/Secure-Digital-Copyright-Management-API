import logging
import json
from datetime import datetime
from typing import Any, Dict
import os
import sys
import logging.handlers

class AuditLogger:
    def __init__(self):
        """Initialize the audit logger with both file and console output"""
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Configure root logger
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate logs
        if not self.logger.handlers:
            # Create formatters
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            console_formatter = logging.Formatter(
                '\033[92m%(asctime)s\033[0m - '  # Green timestamp
                '\033[94m%(levelname)s\033[0m - '  # Blue level
                '%(message)s'  # Normal message
            )
            
            # File handler (rotating file handler to manage log size)
            file_handler = logging.handlers.RotatingFileHandler(
                'logs/audit.log',
                maxBytes=10485760,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
    def _format_log_message(self, message: Dict) -> str:
        """Format log message with color coding for console output"""
        try:
            return json.dumps(message, indent=2)
        except Exception:
            return str(message)
            
    def log_system_event(self, event_type: str, details: dict):
        """Log a system event with details"""
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'details': details
            }
            self.logger.info(self._format_log_message(message))
        except Exception as e:
            print(f"Error logging event: {e}", file=sys.stderr)
            
    def log_auth_attempt(self, user_id: str, success: bool, ip_address: str):
        """Log an authentication attempt"""
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'auth_attempt',
                'user_id': user_id,
                'success': success,
                'ip_address': ip_address
            }
            if success:
                self.logger.info(self._format_log_message(message))
            else:
                self.logger.warning(self._format_log_message(message))
        except Exception as e:
            print(f"Error logging auth attempt: {e}", file=sys.stderr)

    def log_artifact_access(self, user_id: str, artifact_id: str, action: str):
        """Log artifact access"""
        try:
            message = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'artifact_access',
                'user_id': user_id,
                'artifact_id': artifact_id,
                'action': action
            }
            self.logger.info(json.dumps(message))
        except Exception as e:
            print(f"Error logging artifact access: {e}", file=sys.stderr)

    def log_event(self, 
                  event_type: str, 
                  user_id: str, 
                  details: Dict[str, Any],
                  status: str = "success") -> None:
        """Log an audit event"""
        try:
            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "user_id": user_id,
                "status": status,
                "details": details
            }
            self.logger.info(self._format_log_message(event))
        except Exception as e:
            print(f"Error logging event: {e}", file=sys.stderr)

    def log_error(self, error_type: str, error_msg: str, details: Dict[str, Any] = None) -> None:
        """Log an error event"""
        try:
            error = {
                "timestamp": datetime.now().isoformat(),
                "error_type": error_type,
                "error_message": error_msg,
                "details": details or {}
            }
            self.logger.error(self._format_log_message(error))
        except Exception as e:
            print(f"Error logging error: {e}", file=sys.stderr)

    def log_system(self, message: str, level: str = "info") -> None:
        """Log a system event"""
        try:
            formatted_message = {
                "timestamp": datetime.now().isoformat(),
                "type": "system",
                "message": message
            }
            
            if level.lower() == "error":
                self.logger.error(self._format_log_message(formatted_message))
            elif level.lower() == "warning":
                self.logger.warning(self._format_log_message(formatted_message))
            else:
                self.logger.info(self._format_log_message(formatted_message))
        except Exception as e:
            print(f"Error logging system message: {e}", file=sys.stderr)

    def log_auth_attempt(self, 
                        user_id: str, 
                        success: bool, 
                        ip_address: str) -> None:
        """Log authentication attempts"""
        self.log_event(
            "authentication",
            user_id,
            {
                "ip_address": ip_address,
                "success": success
            },
            status="success" if success else "failure"
        ) 