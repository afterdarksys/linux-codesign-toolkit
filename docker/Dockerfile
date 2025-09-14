FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    git \
    curl \
    unzip \
    zip \
    openjdk-11-jdk \
    xar \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create directories
RUN mkdir -p /app/uploads /app/certificates /app/keystores

# Copy application code
COPY src/ ./src/
COPY codesign-toolkit.sh ./
COPY scripts/ ./scripts/

# Clone and build osslsigncode
RUN git clone https://github.com/mtrojnar/osslsigncode.git && \
    cd osslsigncode && \
    mkdir build && \
    cd build && \
    cmake -S .. && \
    cmake --build . && \
    cmake --install .

# Make scripts executable
RUN chmod +x codesign-toolkit.sh
RUN chmod +x scripts/*.py

# Create non-root user
RUN useradd -m -u 1000 codesign && \
    chown -R codesign:codesign /app
USER codesign

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python", "-m", "src.codesign_api.main"]