# Secure Digital Copyright Management System

A secure API and CLI-based application for managing digital copyright artifacts with role-based access control, encryption, and support for various media file types.

## Features

- **Role-Based Access Control (RBAC)**

  - Admin: Full system access
  - Owner: Manage owned artifacts
  - Viewer: Read-only access

- **Security Features**

  - AES-256 encryption for all stored files
  - Bcrypt password hashing with high work factor (12 rounds)
  - JWT-based authentication for API access
  - Secure password requirements enforcement
  - File integrity verification with checksums
  - Rate limiting for login attempts
  - Account lockout protection
  - Comprehensive audit logging
  - Path traversal protection
  - Secure file size validation

- **API Features**

  - RESTful API built with FastAPI
  - Swagger/OpenAPI documentation
  - Token-based authentication
  - Rate limiting
  - Input validation
  - Error handling

- **Media File Support**
  - Audio: MP3, WAV
  - Video: MP4, AVI
  - Documents: PDF, DOC, DOCX
  - Text: Lyrics, musical scores
  - File size limit: 100MB
  - Automatic content type detection
  - Media metadata preservation

## Installation

### Using Docker (Recommended)

1. Clone the repository:

```bash
git clone [repository-url]
cd [repository-name]
```

2. Build and run using Docker Compose:

```bash
docker-compose up --build
```

This will start both the API server and the CLI application in containers.

### Manual Installation

1. Clone the repository:

```bash
git clone [repository-url]
cd [repository-name]
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Initialize the database and set up secure passwords:

```bash
python src/init_db.py
```

During initialization, you'll be prompted to create secure passwords for the default users. Passwords must meet these requirements:

- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&\*(),.?":{}|<>)
- No common patterns or repeated characters

## Project Structure

```
├── src/
│   ├── api/          # FastAPI routes and endpoints
│   ├── auth/         # Authentication and authorization
│   ├── client/       # CLI client implementation
│   ├── encryption/   # Encryption/decryption utilities
│   ├── models/       # Data models and schemas
│   ├── services/     # Business logic services
│   ├── storage/      # File storage management
│   ├── utils/        # Helper utilities
│   ├── cli.py        # CLI interface
│   └── main.py       # API server entry point
├── tests/            # Test suite
├── artifacts/        # Encrypted artifact storage
├── certs/           # SSL/TLS certificates
├── data/            # Application data
├── logs/            # Application logs
├── scripts/         # Utility scripts
└── secure_storage/  # Secure file storage
```

## Default Users

The system comes with three default user roles:

1. Admin User

   - Username: admin
   - Full system access
   - Create during initialization

2. Owner User

   - Username: owner
   - Can manage own artifacts
   - Create during initialization

3. Viewer User
   - Username: viewer
   - Read-only access
   - Create during initialization

## Usage

The application consists of two components that need to be started in sequence:

### 1. Start the Backend API Server

First, start the backend API server using one of these methods:

#### Using Docker (Recommended):

```bash
# Build and start the API server
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build
```

#### Manual Method:

```bash
# Activate virtual environment first
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Start the API server
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

The API server will be available at:

- API Endpoint: http://localhost:8000
- API Documentation: http://localhost:8000/docs
- ReDoc Documentation: http://localhost:8000/redoc

### 2. Start the CLI Application

After the API server is running, open a new terminal and start the CLI application:

```bash
# Activate virtual environment if running manually
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Start the CLI application
python main.py
```

You will see the main menu:

```
Digital Copyright Management System
==================================
1. Login
2. Exit
```

### 3. Login with Default Credentials

The system comes with three default users:

1. Admin User

   - Username: `admin`
   - Password: `Adm!nCtr1#2024`
   - Full system access

2. Owner User

   - Username: `owner`
   - Password: `Own3rSh!p$2024`
   - Can manage owned artifacts

3. Viewer User
   - Username: `viewer`
   - Password: `V!ewUs3r@2024`
   - Read-only access

### 4. User Menu

After logging in, you'll see options based on your role:

```
Welcome [username]!
1. Upload artifact
2. Download artifact
3. List artifacts
4. Show my info
5. Create user (Admin only)
6. Delete artifact (Admin/Owner only)
7. Logout
8. Exit
```

### Troubleshooting

1. If you see connection errors in the CLI:

   - Make sure the API server is running and accessible
   - Check if port 8000 is not being used by another application
   - Verify that the API server started without errors

2. If login fails:

   - Ensure you're using the correct credentials
   - Check if the database was initialized properly
   - Verify that the API server logs show the login attempt

3. If you can't upload/download artifacts:
   - Check if the necessary directories exist
   - Verify you have the correct permissions
   - Ensure the file size is within limits (100MB)

## API Documentation

The API documentation is available at:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Key API Endpoints

- `POST /auth/token` - Get authentication token
- `GET /artifacts` - List available artifacts
- `POST /artifacts/upload` - Upload new artifact
- `GET /artifacts/{id}/download` - Download artifact
- `DELETE /artifacts/{id}` - Delete artifact
- `GET /users/me` - Get current user info

## Development

### Code Quality Tools

The project uses several tools to maintain code quality:

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Security checks
bandit -r src/

# Run pre-commit hooks
pre-commit run --all-files
```

### Running Tests

```bash
# Run tests with coverage
pytest --cov=src tests/

# Generate HTML coverage report
pytest --cov=src --cov-report=html tests/
```

## Security Best Practices

1. Password Security:

   - Never share or store passwords in plain text
   - Use unique, strong passwords for each account
   - Change passwords regularly
   - Use password manager for secure storage

2. System Security:

   - Keep the system and dependencies updated
   - Monitor audit logs regularly
   - Backup database securely
   - Use secure communication channels
   - Enable SSL/TLS for API communication
   - Regular security audits

3. File Security:
   - Verify file integrity after transfers
   - Scan uploads for malware
   - Maintain secure backups
   - Follow least privilege principle
   - Regular backup verification

## Environment Variables

Create a `.env` file with the following variables:

```
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
DATABASE_URL=sqlite:///./secure_dcm.db
STORAGE_PATH=./secure_storage
MAX_FILE_SIZE=104857600
```

## Design Patterns Used

1. **Facade Pattern** (SecureEnclaveService)

   - Simplifies complex security and storage operations
   - Provides unified interface for all security operations

2. **Strategy Pattern** (Authorization)

   - Flexible permission checking implementation
   - Allows for different authorization strategies

3. **Command Pattern** (Upload/Download operations)

   - Encapsulates file operation requests
   - Provides uniform interface for different operations

4. **Template Method Pattern** (File operations)

   - Defines skeleton of operations
   - Allows for customization of specific steps

5. **Dependency Injection**
   - Loose coupling between components
   - Easier testing and maintenance

## Testing

Run the test suite with coverage reporting:

```bash
python -m tests.run_tests
```

This will:

- Run all unit tests
- Generate coverage reports
- Create detailed HTML coverage report

Run security checks:

```bash
bandit -r src/
```

Run type checking:

```bash
mypy src/
```

## File Type Support

The system supports various file types with appropriate handling:

1. **Audio Files**

   - MP3 (.mp3)
   - WAV (.wav)
   - Automatic metadata extraction
   - Content validation

2. **Video Files**

   - MP4 (.mp4)
   - AVI (.avi)
   - Size validation
   - Format verification

3. **Documents**

   - PDF (.pdf)
   - DOC (.doc)
   - DOCX (.docx)
   - Text validation

4. **Copyright Materials**
   - Lyrics (.txt)
   - Musical scores (.pdf)
   - Metadata preservation

## Error Handling

The system provides comprehensive error handling:

1. **Upload Errors**

   - File size validation
   - Format verification
   - Permission checks
   - Encryption failures

2. **Download Errors**

   - File integrity checks
   - Decryption verification
   - Permission validation

3. **User Errors**
   - Invalid credentials
   - Permission denied
   - Rate limiting
   - Account lockout

## Artifact IDs

- Automatically generated using UUID v4
- Guaranteed uniqueness across the system
- Used for all artifact operations (download, delete, etc.)
- Shown in the artifact listing table

## Contributing

Guidelines for contributing to the project:

1. Fork the repository
2. Create a feature branch
3. Make your changes following the coding standards
4. Add tests for new functionality
5. Submit a pull request with a clear description

## License

[Insert License Information]
