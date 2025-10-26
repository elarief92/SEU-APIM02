"""
Web app URL Configuration

This app manages access to the API including token creation and management.
"""

from django.urls import path
from . import views

app_name = 'web'

urlpatterns = [
    # Authentication URLs
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # SSO URLs
    path('sso/login/', views.sso_login, name='sso_login'),
    path('sso/callback/', views.sso_callback, name='sso_callback'),
    
    # Dashboard
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # Token Management
    path('tokens/', views.tokens_list_view, name='tokens_list'),
    path('tokens/create/', views.token_create_view, name='token_create'),
    path('tokens/<uuid:token_id>/', views.token_detail_view, name='token_detail'),
    path('tokens/<uuid:token_id>/permissions/', views.token_permissions_view, name='token_permissions'),
    path('tokens/<uuid:token_id>/revoke/', views.token_revoke_view, name='token_revoke'),
    path('tokens/<uuid:token_id>/activate/', views.token_activate_view, name='token_activate'),
    path('tokens/<uuid:token_id>/refresh/', views.token_refresh_view, name='token_refresh'),
    
    # Logs Viewer
    path('logs/', views.logs_viewer_view, name='logs_viewer'),
    
    # API Endpoints
    path('api/metrics/', views.system_metrics_view, name='system_metrics'),
]

