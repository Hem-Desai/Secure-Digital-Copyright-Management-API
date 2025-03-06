FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Generate SSL certificates
RUN python scripts/generate_certs.py

# Create necessary directories
RUN mkdir -p data logs

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "certs/key.pem", "--ssl-certfile", "certs/cert.pem"] 