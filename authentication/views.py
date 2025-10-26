from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.utils import timezone
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import TokenUser, APIToken, AdminUser
import secrets


class TokenRefreshView(APIView):
    """Refresh access token using refresh token."""
    
    permission_classes = [AllowAny]
    
    def post(self, request):
        """Refresh access token."""
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({
                'error': 'refresh_token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Find refresh token
            api_token = APIToken.objects.select_related('token_user').get(
                token=refresh_token,
                token_type='refresh',
                is_active=True
            )
            
            if not api_token.is_valid():
                return Response({
                    'error': 'Refresh token is expired, revoked, or user is inactive'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Create new access token
            token_user = api_token.token_user
            new_access_token = secrets.token_urlsafe(32)
            access_expires = timezone.now() + timezone.timedelta(hours=token_user.access_token_lifetime_hours)
            
            # Create new access token record
            APIToken.objects.create(
                token_user=token_user,
                token=new_access_token,
                token_type='access',
                expires_at=access_expires,
                name=f"Refreshed Access Token - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
            )
            
            # Update refresh token usage
            from .token_auth import get_client_ip, get_user_agent
            api_token.use_token(get_client_ip(request), get_user_agent(request))
            
            response_data = {
                'access_token': new_access_token,
                'token_type': 'Bearer',
                'expires_in': int(timezone.timedelta(hours=token_user.access_token_lifetime_hours).total_seconds()),
                'expires_at': access_expires.isoformat()
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except APIToken.DoesNotExist:
            return Response({
                'error': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)


class TokenHealthView(APIView):
    """Validate token health/status endpoint."""
    
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Check token health using GET method."""
        return self._validate_token(request)
    
    def post(self, request):
        """Check token health using POST method."""
        return self._validate_token(request)
    
    def _validate_token(self, request):
        """Internal method to validate token."""
        # Get token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header:
            return Response({
                'valid': False,
                'error': 'Authorization header is required',
                'details': 'Provide token in Authorization header as: Bearer <your_token>'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Parse Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return Response({
                'valid': False,
                'error': 'Invalid authorization header format',
                'details': 'Authorization header must be: Bearer <your_token>'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        token_string = parts[1]
        
        try:
            # Find the token in database
            api_token = APIToken.objects.select_related('token_user').get(
                token=token_string,
                token_type='access',
                is_active=True
            )
            
            # Check if token is valid
            if not api_token.is_valid():
                return Response({
                    'valid': False,
                    'error': 'Token is expired, revoked, or user is inactive',
                    'details': {
                        'token_status': 'invalid',
                        'is_active': api_token.is_active,
                        'is_expired': api_token.is_expired(),
                        'user_active': api_token.token_user.is_active,
                        'expires_at': api_token.expires_at.isoformat() if api_token.expires_at else None
                    }
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Update token usage (optional - you might want to track health checks)
            from .token_auth import get_client_ip, get_user_agent
            ip_address = get_client_ip(request)
            user_agent = get_user_agent(request)
            
            # Get token info without incrementing usage count
            time_until_expiry = (api_token.expires_at - timezone.now()).total_seconds()
            hours_until_expiry = int(time_until_expiry // 3600)
            minutes_until_expiry = int((time_until_expiry % 3600) // 60)
            
            # Return successful validation response
            return Response({
                'valid': True,
                'message': 'Token is valid and active',
                'token_info': {
                    'token_type': api_token.token_type,
                    'user': {
                        'name': api_token.token_user.name,
                        'email': api_token.token_user.email,
                        'company': api_token.token_user.company
                    },
                    'expires_at': api_token.expires_at.isoformat(),
                    'expires_in_seconds': int(time_until_expiry),
                    'expires_in_hours': hours_until_expiry,
                    'expires_in_display': f"{hours_until_expiry}h {minutes_until_expiry}m",
                    'usage_count': api_token.usage_count,
                    'last_used': api_token.last_used.isoformat() if api_token.last_used else None,
                    'created_at': api_token.created_at.isoformat()
                },
                'health_check': {
                    'timestamp': timezone.now().isoformat(),
                    'client_ip': ip_address,
                    'user_agent': user_agent[:100] + '...' if len(user_agent) > 100 else user_agent
                }
            }, status=status.HTTP_200_OK)
            
        except APIToken.DoesNotExist:
            return Response({
                'valid': False,
                'error': 'Invalid token',
                'details': 'Token not found in database or not an access token'
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({
                'valid': False,
                'error': 'Token validation error',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

