"""
URL configuration for APIs app.
"""
from django.urls import path, include


urlpatterns = [
    path('v1/', include('apis.v1_urls')),
] 