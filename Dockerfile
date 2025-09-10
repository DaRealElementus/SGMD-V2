FROM python:3.11

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ffmpeg \
        libsndfile1 \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements_server.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements_server.txt

# Copy project files
COPY . .

# Expose Flask port
EXPOSE 5000

# Default command
CMD ["python", "Server.py"]