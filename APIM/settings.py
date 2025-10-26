"""
Django settings for SEU APIs project.

This is the API-only Django project split from the main SEU Tools application.
It contains only API endpoints, authentication, and data models.
"""

from pathlib import Path
import os
from decouple import config
from urllib.parse import urlparse

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-change-this-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True  # Set to False in production

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1,0.0.0.0,testserver', cast=lambda v: [s.strip() for s in v.split(',')])

# External Service Configuration
YAQEEN_BASE_URL = config('YAQEEN_BASE_URL', default='none')
YAQEEN_USERNAME = config('YAQEEN_USERNAME', default='none')
YAQEEN_PASSWORD = config('YAQEEN_PASSWORD', default='none')

# Threading Configuration for external APIs
NATIONAL_ADDRESS_THREADING_ENABLED = config('NATIONAL_ADDRESS_THREADING_ENABLED', default=True, cast=bool)
NATIONAL_ADDRESS_MAX_WORKERS = config('NATIONAL_ADDRESS_MAX_WORKERS', default=10, cast=int)
NATIONAL_ADDRESS_MAX_WORKERS_LIMIT = config('NATIONAL_ADDRESS_MAX_WORKERS_LIMIT', default=50, cast=int)

YAQEEN_THREADING_ENABLED = config('YAQEEN_THREADING_ENABLED', default=True, cast=bool)
YAQEEN_MAX_WORKERS = config('YAQEEN_MAX_WORKERS', default=10, cast=int)
YAQEEN_MAX_WORKERS_LIMIT = config('YAQEEN_MAX_WORKERS_LIMIT', default=50, cast=int)

# Oracle Database Configuration for Banner Integration
ORACLE_DB_USER = config('ORACLE_DB_USER', default='baninst1')
ORACLE_DB_PASSWORD = config('ORACLE_DB_PASSWORD', default='password')
ORACLE_DB_DSN = config('ORACLE_DB_DSN', default='localhost:1521/ORCL')

# WSO2 SSO Configuration (OAuth2/OpenID Connect)
WSO2_SSO_ENABLED = config('WSO2_SSO_ENABLED', default=False, cast=bool)
WSO2_CLIENT_ID = config('WSO2_CLIENT_ID', default='your_client_id')
WSO2_CLIENT_SECRET = config('WSO2_CLIENT_SECRET', default='your_client_secret')
WSO2_AUTHORIZATION_URL = config('WSO2_AUTHORIZATION_URL', default='https://your-wso2-server.com/oauth2/authorize')
WSO2_TOKEN_URL = config('WSO2_TOKEN_URL', default='https://your-wso2-server.com/oauth2/token')
WSO2_USERINFO_URL = config('WSO2_USERINFO_URL', default='https://your-wso2-server.com/oauth2/userinfo')
WSO2_REDIRECT_URI = config('WSO2_REDIRECT_URI', default='http://localhost:8000/web/sso/callback/')
WSO2_SCOPE = config('WSO2_SCOPE', default='openid profile email')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party apps
    'rest_framework',
    'drf_yasg',
    'corsheaders',
    'import_export',
    
    # Local apps
    'authentication',
    'apis',
    'web',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'authentication.middleware.APIRequestLoggingMiddleware',  # Log API requests with app names
]

# CORS settings for API access
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # React development server
    "http://localhost:8080",  # Vue development server
    "http://127.0.0.1:8001",  # SEU Web project
    "http://localhost:8001",
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_ALL_ORIGINS = DEBUG  # Only allow all origins in development

ROOT_URLCONF = 'APIM.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # No templates needed for API-only project
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'APIM.wsgi.application'

# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL')

if DATABASE_URL and DATABASE_URL.startswith('postgresql://'):
    # Parse PostgreSQL URL from environment variable
    url = urlparse(DATABASE_URL)
    
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': url.path[1:],  # Remove leading '/'
            'USER': url.username,
            'PASSWORD': url.password,
            'HOST': url.hostname,
            'PORT': url.port,
            'OPTIONS': {
                'sslmode': 'require',
            },
        }
    }
    print(f"✅ Using PostgreSQL database: {url.hostname}/{url.path[1:]}")
else:
    # Fallback to SQLite (for local development)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'seu_apis.db',
        }
    }
    print("⚠️ Using SQLite database (fallback)")

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Riyadh'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# No custom user model needed - using token-based authentication

# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'authentication.token_auth.SimpleTokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
        'authentication.permissions.HasEndpointPermission',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'EXCEPTION_HANDLER': 'authentication.exception_handler.custom_exception_handler',
}

# Swagger/OpenAPI Documentation
SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'JWT authorization header using the Bearer scheme. Example: "Authorization: Bearer {token}"'
        }
    },
    'USE_SESSION_AUTH': False,
    'JSON_EDITOR': True,
    'SUPPORTED_SUBMIT_METHODS': [
        'get',
        'post',
        'put',
        'delete',
        'patch'
    ],
    'OPERATIONS_SORTER': 'alpha',
    'TAGS_SORTER': 'alpha',
    'DOC_EXPANSION': 'none',
    'DEEP_LINKING': True,
    'SHOW_EXTENSIONS': True,
    'DEFAULT_MODEL_RENDERING': 'example'
}

REDOC_SETTINGS = {
    'LAZY_RENDERING': False,
}

# Token Settings
DEFAULT_ACCESS_TOKEN_LIFETIME_HOURS = 24  # 24 hours
DEFAULT_REFRESH_TOKEN_LIFETIME_DAYS = 30  # 30 days
ADMIN_SECRET_TOKEN = config('ADMIN_SECRET_TOKEN', default='admin_secret_token_2024')

# Create logs directory if it doesn't exist
LOGS_DIR = config('LOGS_DIR', default=BASE_DIR / 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

# Detailed Logging Configuration for APIs
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '[{asctime}] {levelname:8} {name:20} | {message} | File: {pathname}:{lineno}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'error_detailed': {
            'format': (
                '[{asctime}] {levelname:8} {name:20}\n'
                'Message: {message}\n'
                'File: {pathname}:{lineno}\n'
                'Function: {funcName}\n'
            ),
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'simple': {
            'format': '[{asctime}] {levelname:8} | {message}',
            'style': '{',
            'datefmt': '%H:%M:%S',
        },
        'api': {
            'format': '[{asctime}] {levelname:8} API | {message} | Module: {module}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'level': 'WARNING',  # Only show warnings and errors in console
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file_api': {
            # API requests and responses ONLY
            'level': 'WARNING',  # Only errors and warnings
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOGS_DIR, 'api.log'),
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'api',
            'encoding': 'utf-8',
        },
        'file_error': {
            # All errors and exceptions with full tracebacks
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOGS_DIR, 'errors.log'),
            'maxBytes': 1024*1024*20,  # 20MB
            'backupCount': 20,
            'formatter': 'error_detailed',
            'encoding': 'utf-8',
        },
        'file_app': {
            # General application logs (web interface, authentication, etc.)
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOGS_DIR, 'app.log'),
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 5,
            'formatter': 'detailed',
            'encoding': 'utf-8',
        },
    },
    'loggers': {
        'apis': {
            # API views and middleware - goes to api.log for errors/warnings only
            'handlers': ['console', 'file_api', 'file_error'],
            'level': 'WARNING',  # Only log warnings and errors (not successful requests)
            'propagate': False,
        },
        'authentication': {
            # Authentication and permissions - goes to app.log
            'handlers': ['console', 'file_app', 'file_error'],
            'level': 'WARNING',  # Only log warnings and errors
            'propagate': False,
        },
        'web': {
            # Web interface - goes to app.log
            'handlers': ['console', 'file_app', 'file_error'],
            'level': 'INFO',  # Web interface can keep INFO level
            'propagate': False,
        },
        'django': {
            # Django framework - goes to app.log
            'handlers': ['file_app'],
            'level': 'WARNING',  # Only warnings and errors
            'propagate': False,
        },
        'django.request': {
            # Django request errors - goes to errors.log
            'handlers': ['console', 'file_error'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.server': {
            # Django development server - minimal logging
            'handlers': [],  # Don't log - already goes to seu_apis.log
            'level': 'ERROR',
            'propagate': False,
        },
        '': {
            # Root logger - catch-all for any unconfigured loggers
            'handlers': ['console', 'file_app', 'file_error'],
            'level': 'WARNING',
        },
    },
}

# PostgreSQL 13 Compatibility Workaround for Django 5.x
# Add this at the VERY END of your settings.py file

import django
from django.db.backends.postgresql.base import DatabaseWrapper

# Store the original method
_original_check_database_version_supported = DatabaseWrapper.check_database_version_supported

# Create a patched version
def _patched_check_database_version_supported(self):
    try:
        # Try the original check first
        _original_check_database_version_supported(self)
    except django.core.exceptions.ImproperlyConfigured as e:
        # If it's the PostgreSQL version error, ignore it
        if "PostgreSQL 14 or later is required" in str(e):
            print("⚠️  PostgreSQL 13 detected - bypassing version check for compatibility")
            return
        # Re-raise any other errors
        raise

# Apply the patch
DatabaseWrapper.check_database_version_supported = _patched_check_database_version_supported