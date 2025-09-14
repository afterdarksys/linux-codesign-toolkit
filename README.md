# Linux Code Signing Toolkit 2.0

A comprehensive toolkit for code signing Windows binaries, Java applications, AIR files, and Apple packages on Linux and macOS systems. **Now with enterprise-grade REST API and full regulatory compliance!**

**Designed and Developed by:** Ryan Coleman <coleman.ryan@gmail.com>

## 🚀 What's New in v2.0

### **Modern REST API**
- **FastAPI-based web service** with interactive documentation
- **Background processing** for signing operations
- **File upload/download** with secure storage
- **Database-backed** operation tracking and audit trails
- **Full backward compatibility** with existing bash CLI

### **Enterprise Compliance**
- ✅ **SOX** (Sarbanes-Oxley) - 7-year audit retention
- ✅ **GLBA** (Gramm-Leach-Bliley) - Financial data protection
- ✅ **PCI-DSS** - Payment card security standards
- ✅ **GDPR** - EU data protection regulation

### **Enhanced Security**
- **AES-256 encryption** for data at rest
- **API key authentication** with role-based permissions
- **Comprehensive audit logging** for all operations
- **Automated security monitoring** and threat detection

## Features

### **Core Signing Capabilities**
- **Windows Binary Signing**: Sign PE, CAB, CAT, MSI, APPX, and script files using osslsigncode
- **Java Code Signing**: Support for JAR signing using jarsigner and keytool
- **AIR File Signing**: Sign Adobe AIR (.air) files for distribution
- **Apple Package Signing**: Sign macOS packages (.pkg), iOS apps (.ipa), and macOS apps (.app)
- **Signature Management**: Sign, unsign, resign, verify, and delete signatures
- **Timestamp Support**: Add trusted timestamps for long-term signature validity

### **Enterprise Features (v2.0)**
- **REST API**: Modern web API with comprehensive endpoints
- **Database Tracking**: SQLite database for operations, users, and audit logs
- **User Management**: API key-based authentication and authorization
- **File Management**: Secure upload, storage, and download system
- **Audit Trails**: Complete compliance logging for SOX, GLBA, PCI-DSS, GDPR
- **Security Monitoring**: Automated threat detection and alerting
- **Data Encryption**: AES-256 encryption for sensitive data
- **GDPR Rights**: Data portability and erasure capabilities

## Supported Operations

### Windows Binaries (via osslsigncode)
- Sign executables with Authenticode certificates
- Add timestamps to signatures (recommended for long-term validity)
- Verify existing signatures
- Remove signatures (where applicable)
- Resign files with new certificates

### Java Applications (via JDK tools)
- Sign JAR files with jarsigner
- Create and manage keystores with keytool
- Verify JAR signatures
- Manage certificate chains

### Adobe AIR Files
- Sign AIR files for distribution
- Verify AIR signatures
- Manage AIR certificates
- Support for timestamping (PKCS#7 timestamps)

### Apple Packages
- Sign macOS installer packages (.pkg)
- Sign iOS applications (.ipa)
- Sign macOS applications (.app)
- Support for timestamping (where applicable)
- Support for notarization workflows

## Prerequisites

- CMake 3.17 or newer
- OpenSSL development libraries
- Java Development Kit (JDK) 8 or newer
- Build tools (gcc/clang, make)
- xar (for macOS package signing)
- isign (for iOS app signing on Linux)

## Quick Start

### Traditional CLI Installation (v1.x compatible)

#### Ubuntu/Debian
```bash
sudo apt update && sudo apt install cmake libssl-dev libcurl4-openssl-dev zlib1g-dev python3 openjdk-11-jdk
# For Apple package signing
pip install isign
```

#### macOS
```bash
brew install cmake pkg-config openssl@1.1 openjdk xar
export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig"
# For iOS signing on macOS
pip install isign
```

#### Build Traditional CLI
```bash
# Clone and build osslsigncode
git clone https://github.com/mtrojnar/osslsigncode.git
cd osslsigncode && mkdir build && cd build
cmake -S .. && cmake --build . && sudo cmake --install .

# Build the toolkit wrapper
cd ../.. && make
```

### **🚀 Modern API Server Installation (v2.0)**

#### Quick Setup
```bash
# Install Python dependencies
pip install -r requirements.txt

# Create admin user
python scripts/create_admin_user.py

# Start the API server
python -m src.codesign_api.main
```

#### Docker Deployment
```bash
# Deploy with Docker Compose
cd docker && docker-compose up -d

# Check status
curl http://localhost:8000/health
```

#### Configuration
```bash
# Copy environment template
cp .env.example .env
# Edit .env with your settings

# Available at:
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
# Health: http://localhost:8000/health
```

## Usage

### **Traditional CLI (All Versions)**
```bash
# Sign a Windows executable
./codesign-toolkit sign -type windows -cert cert.pem -key key.pem -in app.exe -out app-signed.exe

# Sign a JAR file
./codesign-toolkit sign -type java -keystore keystore.jks -alias mykey -in app.jar -out app-signed.jar

# Sign an AIR file
./codesign-toolkit sign -type air -cert air-cert.p12 -pass password -in app.air -out app-signed.air

# Sign an Apple package
./codesign-toolkit sign -type apple -cert apple-cert.p12 -pass password -in app.pkg -out app-signed.pkg

# Verify signatures
./codesign-toolkit verify -in app-signed.exe
./codesign-toolkit unsign -in app-signed.exe -out app-unsigned.exe
```

### **🆕 Modern REST API (v2.0)**

#### Authentication
```bash
# All API calls require authentication
export API_KEY="your-api-key-here"
curl -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/signing/operations
```

#### Sign Files
```bash
# Sign a Windows executable via API
curl -X POST "http://localhost:8000/api/v1/signing/sign" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@app.exe" \
  -F "signing_type=windows" \
  -F "key_id=windows-cert-1" \
  -F "app_name=My Application"

# Verify a signature via API
curl -X POST "http://localhost:8000/api/v1/signing/verify" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@signed-app.exe" \
  -F "signing_type=windows"
```

#### List Operations
```bash
# Get all signing operations
curl -H "X-API-Key: $API_KEY" \
     "http://localhost:8000/api/v1/signing/operations?page=1&per_page=10"

# Download signed file
curl -H "X-API-Key: $API_KEY" \
     "http://localhost:8000/api/v1/download/123/signed?token=abc" \
     -o signed-file.exe
```

#### Admin Operations
```bash
# Create new user (admin only)
curl -X POST "http://localhost:8000/api/v1/admin/users" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "developer1",
    "name": "John Developer",
    "email": "john@company.com",
    "allowed_signing_types": "windows,java"
  }'

# Get compliance status
curl -H "X-API-Key: $ADMIN_KEY" \
     "http://localhost:8000/api/v1/compliance/status"
```

## 📚 Documentation

- **[API_README.md](API_README.md)** - Complete REST API documentation
- **[COMPLIANCE_DOCUMENTATION.md](COMPLIANCE_DOCUMENTATION.md)** - Regulatory compliance guide
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes
- **Interactive API Docs** - Available at `/docs` when server is running

## 🛡️ Compliance & Security

### Regulatory Compliance
- ✅ **SOX (Sarbanes-Oxley)** - 7-year audit retention, complete audit trails
- ✅ **GLBA (Gramm-Leach-Bliley)** - Financial data protection, 5-year retention
- ✅ **PCI-DSS** - Payment security, data encryption, access controls
- ✅ **GDPR** - Data portability, right to erasure, consent management

### Security Features
- **AES-256 Encryption** - All sensitive data encrypted at rest
- **TLS/HTTPS** - Secure data transmission
- **API Key Authentication** - Role-based access control
- **Audit Logging** - Complete operation history
- **Security Monitoring** - Automated threat detection

## 🚀 Deployment Options

### Development
```bash
# Start API server for development
python -m src.codesign_api.main
```

### Production with Docker
```bash
# Production deployment
cd docker && docker-compose up -d

# With SSL/nginx reverse proxy
# Edit docker/nginx.conf for your domain
```

### Traditional CLI Only
```bash
# Build and install CLI tools
make && make install
```

## 🧪 Testing

```bash
# Test API endpoints
python scripts/test_api.py YOUR_API_KEY

# Test traditional CLI
./tests/run-tests.sh
```

## 🔄 Migration from v1.x

**Zero Breaking Changes** - All existing bash commands work exactly as before!

```bash
# v1.x commands still work
./codesign-toolkit sign -type windows -cert cert.pem -key key.pem -in app.exe -out signed.exe

# Plus new v2.0 API capabilities
curl -X POST -H "X-API-Key: $KEY" -F "file=@app.exe" http://localhost:8000/api/v1/signing/sign
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

**Note:** This project incorporates osslsigncode which is licensed under GPL-3.0. The osslsigncode component retains its original GPL-3.0 license, while the toolkit wrapper and additional functionality is MIT licensed.

## 👨‍💻 Author

**Ryan Coleman**
Email: coleman.ryan@gmail.com
GitHub: [Ryan Coleman](https://github.com/ryancoleman)

Designed and developed the Linux Code Signing Toolkit to provide comprehensive cross-platform code signing capabilities for Windows, Java, AIR, and Apple package formats. Extended in v2.0 with enterprise-grade REST API and full regulatory compliance.

---

## 🌟 What Makes This Special

This toolkit bridges the gap between traditional command-line signing tools and modern enterprise requirements:

- **Proven Core** - Built on mature, well-tested signing tools (osslsigncode, jarsigner, etc.)
- **Modern Interface** - REST API for easy integration with CI/CD and web applications
- **Enterprise Ready** - Full compliance with SOX, GLBA, PCI-DSS, and GDPR
- **Zero Migration Pain** - Existing workflows continue to work unchanged
- **Battle Tested** - Used in production environments for critical signing operations

**Version 2.0 transforms a great CLI tool into an enterprise-ready signing service while preserving everything that made the original great!** 🎯
