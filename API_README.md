# Linux Code Signing Toolkit API v2.0

A modern, API-driven code signing service that wraps the existing Linux Code Signing Toolkit with a RESTful web API.

**Designed and Developed by:** Ryan Coleman <coleman.ryan@gmail.com>

## 🚀 Features

### Core Capabilities
- **RESTful API**: Modern FastAPI-based web service
- **Multiple Signing Types**: Windows (PE), Java (JAR), Adobe AIR, Apple packages
- **Authentication**: API key-based authentication system
- **Database Tracking**: SQLite database for operation tracking and audit trails
- **File Management**: Secure file upload, storage, and download system
- **Background Processing**: Asynchronous signing operations
- **Audit Logging**: Comprehensive audit trail for compliance

### API Operations
- **POST /api/v1/signing/sign** - Sign files
- **POST /api/v1/signing/verify** - Verify signatures
- **POST /api/v1/unsign** - Remove signatures (Windows only)
- **POST /api/v1/resign** - Remove and re-sign with new certificate
- **GET /api/v1/signing/operations** - List operations
- **GET /api/v1/download/{id}/{type}** - Download files

### Admin Operations
- **POST /api/v1/admin/users** - Create API users
- **GET /api/v1/admin/users** - List users
- **GET /api/v1/admin/certificates** - List certificates
- **GET /api/v1/admin/audit-log** - View audit logs

## 📋 Database Schema

### Tables Created
- **signing_operations** - Track all signing operations with metadata
- **api_users** - Store API user authentication and permissions
- **certificate_store** - Manage certificates and signing keys
- **audit_log** - Comprehensive audit trail for compliance

Key fields include:
- `timestamp`, `who_signed_the_file`, `filename`, `file_hash`
- `path_to_file_on_disk`, `generated_download_link`
- `signing_type`, `key_id`, `operation_status`

## 🛠️ Installation & Setup

### Prerequisites
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update && sudo apt install -y \
    cmake libssl-dev libcurl4-openssl-dev zlib1g-dev \
    python3.11 python3.11-pip python3.11-dev \
    openjdk-11-jdk git

# Install Python dependencies
pip install -r requirements.txt
```

### Quick Start
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up environment
cp .env.example .env
# Edit .env with your settings

# 3. Create admin user
python scripts/create_admin_user.py

# 4. Start the API server
python -m src.codesign_api.main

# 5. Test the API
python scripts/test_api.py YOUR_API_KEY
```

### Docker Deployment
```bash
# Build and run with Docker Compose
cd docker
docker-compose up -d

# Check health
curl http://localhost:8000/health
```

## 🔐 Authentication

The API uses API key authentication via the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key-here" \
     http://localhost:8000/api/v1/signing/operations
```

Create users with the admin script or via the admin API.

## 📝 API Usage Examples

### Sign a Windows Executable
```bash
curl -X POST "http://localhost:8000/api/v1/signing/sign" \
  -H "X-API-Key: your-api-key" \
  -F "file=@app.exe" \
  -F "signing_type=windows" \
  -F "key_id=windows-cert-1" \
  -F "app_name=My Application"
```

### Verify a Signature
```bash
curl -X POST "http://localhost:8000/api/v1/signing/verify" \
  -H "X-API-Key: your-api-key" \
  -F "file=@signed-app.exe" \
  -F "signing_type=windows"
```

### List Operations
```bash
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8000/api/v1/signing/operations?page=1&per_page=10"
```

### Download Signed File
```bash
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8000/api/v1/download/123/signed?token=abc" \
     -o signed-file.exe
```

## 🔧 Configuration

Key configuration options in `.env`:

```env
# API Settings
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your-secret-key

# Database
DATABASE_URL=sqlite+aiosqlite:///./codesign_api.db

# File Storage
UPLOAD_DIRECTORY=./uploads
MAX_FILE_SIZE=524288000  # 500MB

# Signing Tools
OSSLSIGNCODE_PATH=osslsigncode
JARSIGNER_PATH=jarsigner
CODESIGN_PATH=codesign

# Security
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000
```

## 📊 Monitoring & Health

### Health Check
```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "database_status": "healthy",
  "uptime_seconds": 3600.0
}
```

### Audit Logs
All operations are logged for compliance:
- User authentication events
- File upload/download events
- Signing operations with results
- Administrative actions

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client Apps   │────│   FastAPI Server │────│   SQLite DB     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Bash Toolkit     │
                       │ (osslsigncode,   │
                       │  jarsigner, etc) │
                       └──────────────────┘
```

The API server acts as a modern wrapper around the existing bash-based toolkit, adding:
- Web API interface
- Database persistence
- User management
- File handling
- Audit trails

## 🧪 Testing

Run the test suite:
```bash
# Test without authentication
python scripts/test_api.py

# Test with API key
python scripts/test_api.py YOUR_API_KEY
```

## 🔒 Security Considerations

- API keys are hashed before storage
- File uploads are validated and size-limited
- User permissions control signing type access
- All operations are audit logged
- Files are stored in user-specific directories
- Download links include token validation

## 📚 API Documentation

Interactive API documentation available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🎯 Migration from v1.x

The new API server runs alongside the existing bash toolkit:

1. **Existing CLI still works** - All bash commands unchanged
2. **API provides new interface** - Modern REST API for integration
3. **Database adds persistence** - Operations are now tracked and auditable
4. **Authentication adds security** - Control access with API keys

## 🤝 Contributing

This modernizes the original Linux Code Signing Toolkit while maintaining full backward compatibility. The API server provides enterprise-ready features while the proven bash toolkit handles the actual signing operations.

## 📄 License

MIT License (API components) + GPL-3.0 License (osslsigncode component)

---

**Ryan Coleman**
Email: coleman.ryan@gmail.com
Architect of the modern API layer for the Linux Code Signing Toolkit