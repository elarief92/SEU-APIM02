# SEU APIs Project

## Overview
This is the API-only Django project extracted from the main SEU Tools application. It provides a clean, focused REST API server for all government services and university systems.

## Features

### 🔥 **Core API Endpoints**
- **Noor API** - Student certificate processing (Ministry of Education)
- **Yaqeen API** - National identity verification service
- **Qiyas API** - Qudurat and STEP exam results
- **Disability API** - MOSA disability verification service
- **Social Security API** - MOSA social security information
- **Moahal API** - MOE qualifications verification
- **National Address API** - Wasel national address service
- **Student Info API** - Oracle Banner integration
- **SMS API** - Notification services
- **ERP APIs** - Employee and leave management

### 🔐 **Authentication & Security**
- Token-based authentication

### 📊 **Monitoring & Logging**
- ✅ **Complete logging system** with file-based storage
- ✅ **Structured logging** for all API operations
- ✅ **Configuration-based** logging controls

### 📖 **API Documentation**
- will be implemented

## Project Structure

```
SEU_APIs/
├── 📁 apis/                    # API endpoints and business logic
│   ├── views.py               # All API view classes ✅
│   ├── models.py              # Configuration and history models ✅
│   ├── utils.py               # Helper functions and logging ✅
│   ├── urls.py                # API URL routing ✅
│   └── admin.py               # Admin interface ✅
├── 📁 authentication/          # Authentication system
│   ├── models.py              # User and token models ✅
│   ├── views.py               # Auth endpoints ✅
│   └── urls.py                # Auth URL routing ✅
├── 📁 seu_apis/               # Django project settings
│   ├── settings.py            # API-focused configuration ✅
│   ├── urls.py                # Main URL routing ✅
│   └── wsgi.py                # WSGI application ✅
├── 📁 logs/                   # Log files directory
├── 📄 manage.py               # Django management script ✅
├── 📄 requirements.txt        # Python dependencies ✅
└── 📄 README.md              # This file ✅
```

## Installation & Setup

### 1. **Environment Setup**
```bash
git clone https://github.com/zshaikh-seu/SEU_APIM.git
cd to the project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. **Configuration**
```bash
# Copy environment template
cp env_template.txt .env

# Edit .env with your configuration
nano .env
```

### 3. **Database Setup**
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### 4. **Run Development Server**
```bash
python manage.py runserver 0.0.0.0:8000
```


