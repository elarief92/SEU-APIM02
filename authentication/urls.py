"""
URL configuration for authentication app.
"""
from django.urls import path
from .views import (
    TokenRefreshView,
    TokenHealthView,
)

app_name = 'authentication'

urlpatterns = [
    # Token operations
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh_token'),
    path('token/health/', TokenHealthView.as_view(), name='token_health'),
    
]
