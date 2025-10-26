"""
SEU APIs URL Configuration

This project contains only API endpoints for the SEU Tools system.
All web interface functionality is handled by the separate SEU_Web project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
# from rest_framework import permissions
# from drf_yasg.views import get_schema_view
# from drf_yasg import openapi

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API Documentation
    # path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    # path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    # path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    # path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='api-docs'),
    
    # Authentication endpoints
    path('auth/', include('authentication.urls')),
    
    # Web app for API management
    path('web/', include('web.urls')),
    
    # API endpoints
    path('api/', include('apis.urls')),
]

# Add this to serve static files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)