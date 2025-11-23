FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=APIM.settings

# Create and set the correct working directory
RUN mkdir -p /opt/SEU_APIM/APIM
WORKDIR /opt/SEU_APIM/APIM

# Install system dependencies for MSSQL
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    python3-dev \
    unixodbc-dev \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Add Microsoft ODBC driver for SQL Server (updated approach)
RUN curl -sSL https://packages.microsoft.com/keys/microsoft.asc > /etc/apt/trusted.gpg.d/microsoft.asc \
    && chmod 644 /etc/apt/trusted.gpg.d/microsoft.asc \
    && curl -sSL https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list

# Install MS ODBC Driver 18 for SQL Server
RUN apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 \
    && apt-get install -y unixodbc-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install additional Python packages for MSSQL
RUN pip install --no-cache-dir pyodbc django-mssql-backend

# Copy project
COPY . .

# Create necessary directories
RUN mkdir -p logs staticfiles

# Collect static files
RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Use Gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "APIM.wsgi:application"]