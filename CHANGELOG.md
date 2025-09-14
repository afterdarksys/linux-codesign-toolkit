# Changelog - Linux Code Signing Toolkit

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Designed and Developed by:** Ryan Coleman <coleman.ryan@gmail.com>

---

## [2.0.0] - 2024-09-14

### 🚀 **MAJOR RELEASE - API-Driven Architecture**

This major release modernizes the Linux Code Signing Toolkit with a complete REST API backend while maintaining full backward compatibility with the existing bash-based CLI.

### ✨ **Added - Core API Features**

#### **Modern API Server**
- **FastAPI-based REST API** with async/await support
- **Complete API documentation** with Swagger UI and ReDoc
- **Background processing** for signing operations
- **File upload/download system** with secure storage
- **Health monitoring** and status endpoints

#### **Authentication & Authorization**
- **API key-based authentication** system
- **Role-based permissions** per signing type (windows, java, air, apple)
- **User management** with admin endpoints
- **Session tracking** and API key rotation

#### **Database Integration**
- **SQLite database** for operation tracking and audit trails
- **Comprehensive schema** with 4 main tables:
  - `signing_operations` - Track all signing operations with metadata
  - `api_users` - Store API user authentication and permissions
  - `certificate_store` - Manage certificates and signing keys
  - `audit_log` - Complete audit trail for compliance
- **File metadata tracking** including hashes, timestamps, and paths
- **Download link generation** for secure file retrieval

#### **API Endpoints**
- `POST /api/v1/signing/sign` - Sign files with certificate
- `POST /api/v1/signing/verify` - Verify file signatures
- `POST /api/v1/unsign` - Remove signatures (Windows only)
- `POST /api/v1/resign` - Remove and re-sign with new certificate
- `GET /api/v1/signing/operations` - List user operations with pagination
- `GET /api/v1/signing/operations/{id}` - Get specific operation details
- `GET /api/v1/download/{id}/{type}` - Download original or signed files

#### **Admin Endpoints**
- `POST /api/v1/admin/users` - Create API users
- `GET /api/v1/admin/users` - List all users
- `GET /api/v1/admin/users/{id}` - Get user details
- `PUT /api/v1/admin/users/{id}/activate` - Activate user account
- `PUT /api/v1/admin/users/{id}/deactivate` - Deactivate user account
- `DELETE /api/v1/admin/users/{id}` - Delete user account
- `GET /api/v1/admin/certificates` - List certificates
- `GET /api/v1/admin/audit-log` - View audit logs

### 🛡️ **Added - Enterprise Compliance**

#### **SOX (Sarbanes-Oxley) Compliance**
- **7-year audit log retention** policy
- **Complete audit trail** for all operations
- **Data integrity verification** with SHA-256 file hashes
- **Non-repudiation** through cryptographic signatures
- **Change tracking** for all system modifications

#### **GLBA (Gramm-Leach-Bliley) Compliance**
- **5-year data retention** for customer information
- **Data encryption** for sensitive information
- **Access controls** and authentication
- **Privacy safeguards** for customer data

#### **PCI-DSS Compliance**
- **Data encryption at rest** (AES-256) and in transit (TLS)
- **Access controls** with unique user IDs
- **Comprehensive audit logging** (Requirement 10)
- **Security monitoring** with suspicious activity detection
- **Secure authentication** with API keys

#### **GDPR Compliance**
- **Right to Data Portability** (Article 20) - `GET /api/v1/compliance/gdpr/export/{user_id}`
- **Right to Erasure** (Article 17) - `DELETE /api/v1/compliance/gdpr/delete/{user_id}`
- **Consent Management** (Article 7) - `POST /api/v1/compliance/gdpr/consent-withdrawal/{user_id}`
- **Data Protection by Design** - Built-in privacy features
- **Data encryption** and pseudonymization

#### **Compliance Features**
- **Automated data retention** policies with cleanup procedures
- **Security monitoring** and threat detection
- **Compliance reporting** with SOX and PCI-DSS reports
- **Data subject rights** management
- **Audit trail** preservation during data deletion

### 🔐 **Added - Security Enhancements**

#### **Encryption & Key Management**
- **AES-256 encryption** for sensitive data at rest
- **PBKDF2 key derivation** with 100,000 iterations
- **Secure key storage** with restricted file permissions
- **Automatic key rotation** capabilities
- **Password-based certificate encryption**

#### **Authentication Security**
- **API key hashing** with bcrypt
- **Failed authentication tracking**
- **Suspicious activity detection**
- **Rate limiting** support (configurable)
- **IP address logging** for audit trails

#### **Data Protection**
- **PII hashing** for privacy protection
- **Secure file storage** in user-specific directories
- **File integrity verification** with checksums
- **Secure deletion** procedures for GDPR compliance

### 🏗️ **Added - Infrastructure**

#### **Docker Support**
- **Multi-stage Dockerfile** for production deployment
- **Docker Compose** configuration with nginx reverse proxy
- **Health checks** and monitoring
- **Volume management** for persistent data

#### **Configuration Management**
- **Environment-based configuration** with `.env` support
- **Configurable retention policies**
- **Flexible signing tool paths**
- **Rate limiting and security settings**

#### **Monitoring & Health**
- **Health check endpoint** with database connectivity
- **Request/response logging** with timing
- **Error handling** with detailed logging
- **Performance monitoring** capabilities

### 🛠️ **Added - Developer Tools**

#### **Admin Scripts**
- `scripts/create_admin_user.py` - Create initial admin users
- `scripts/test_api.py` - Comprehensive API testing suite

#### **Testing & Validation**
- **Automated API testing** with authentication
- **File upload/download testing**
- **Health check validation**
- **Compliance feature testing**

#### **Documentation**
- **API_README.md** - Complete API documentation
- **COMPLIANCE_DOCUMENTATION.md** - Regulatory compliance guide
- **Interactive API docs** at `/docs` and `/redoc`

### 📦 **Added - Package Management**

#### **Python Packaging**
- **pyproject.toml** for modern Python packaging
- **requirements.txt** with all dependencies
- **Entry point scripts** for CLI usage

#### **Dependencies**
- **FastAPI** - Modern web framework
- **Uvicorn** - ASGI server
- **SQLAlchemy** - Database ORM with async support
- **Pydantic** - Data validation and settings
- **Cryptography** - Encryption and security
- **Aiofiles** - Async file operations

### 🔄 **Changed**

#### **Architecture**
- **Hybrid deployment model** - Bash toolkit + REST API
- **Async/await pattern** throughout the codebase
- **Database-backed operations** instead of file-based tracking
- **Background task processing** for long-running operations

#### **Configuration**
- **Environment variable configuration** replacing hardcoded values
- **Configurable paths** for all tools and storage locations
- **Flexible authentication** and authorization settings

### 🏗️ **Infrastructure**

#### **Database Schema**
```sql
-- Core tables for v2.0
CREATE TABLE signing_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_type VARCHAR(20) NOT NULL,
    signing_type VARCHAR(20) NOT NULL,
    who_signed_the_file VARCHAR(100) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    file_hash VARCHAR(64) NOT NULL,
    path_to_file_on_disk VARCHAR(500) NOT NULL,
    generated_download_link VARCHAR(500)
);

CREATE TABLE api_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id VARCHAR(50) UNIQUE NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL,
    allowed_signing_types VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE
);
```

### ✅ **Backward Compatibility**

#### **Existing Features Preserved**
- **All bash CLI commands** work exactly as before
- **Same signing capabilities** for Windows, Java, AIR, Apple
- **Same certificate management** and tool integration
- **Existing scripts and workflows** remain functional

#### **Migration Path**
- **Gradual adoption** - Use CLI or API as needed
- **No breaking changes** to existing automation
- **Enhanced capabilities** through API while preserving CLI

---

## [1.2.0] - 2024-08-22

### Added
- **JIRA Integration** for audit trails and compliance
- **Enhanced timestamp support** for long-term signature validity
- **Improved error handling** and logging
- **Additional certificate format support**

### Fixed
- **AIR file signing** compatibility issues
- **Apple package verification** on Linux systems
- **Timestamp server reliability** improvements

### Changed
- **Enhanced logging output** with color coding
- **Improved dependency checking** during installation

---

## [1.1.0] - 2024-08-22

### Added
- **Enhanced timestamp support** and verification
- **Improved certificate validation**
- **Better error messages** and troubleshooting guides

### Fixed
- **macOS compatibility** issues with xar and codesign
- **Java keystore handling** edge cases
- **Windows PE signature verification** accuracy

### Changed
- **Streamlined installation process**
- **Updated documentation** with more examples

---

## [1.0.0] - 2024-08-22

### Added
- **Initial release** of Linux Code Signing Toolkit
- **Windows binary signing** via osslsigncode
- **Java JAR signing** via jarsigner
- **Adobe AIR file signing**
- **Apple package signing** (.pkg, .ipa, .app)
- **Cross-platform support** (Linux and macOS)
- **Comprehensive documentation**
- **Example scripts** and usage guides
- **MIT licensing** with GPL components preserved

### Features
- **Multi-format support** - PE, CAB, MSI, JAR, AIR, PKG, IPA, APP
- **Timestamp support** for long-term validity
- **Certificate management** utilities
- **Verification capabilities** for all supported formats
- **Signature removal** where applicable
- **Build system** with Make and CMake

---

## Migration Guide

### From v1.x to v2.0

#### **Existing Users**
- **No action required** - All existing bash commands continue to work
- **Optional upgrade** - Start using API endpoints for new integrations
- **Enhanced features** - Access to database tracking and compliance features

#### **New Integrations**
- **Start with API** - Use REST endpoints for modern applications
- **Web-based workflows** - Build web UIs on top of the API
- **Enterprise features** - Leverage compliance and audit capabilities

#### **Installation Options**
```bash
# Traditional CLI (v1.x compatible)
make install

# Modern API server (v2.0)
pip install -r requirements.txt
python -m src.codesign_api.main

# Docker deployment (v2.0)
cd docker && docker-compose up -d
```

---

**For detailed API documentation, see [API_README.md](API_README.md)**
**For compliance information, see [COMPLIANCE_DOCUMENTATION.md](COMPLIANCE_DOCUMENTATION.md)**