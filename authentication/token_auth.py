from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import APIToken


def get_client_ip(request):
    """Get the client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Get the user agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')


class SimpleTokenAuthentication(BaseAuthentication):
    """Simple token authentication using Bearer tokens."""
    
    keyword = 'Bearer'
    
    def authenticate(self, request):
        """Authenticate the request using Bearer token."""
        auth_header = self.get_auth_header(request)
        if not auth_header:
            return None
        
        try:
            token = self.get_token_from_header(auth_header)
            if not token:
                return None
            
            return self.authenticate_token(token, request)
            
        except AuthenticationFailed:
            raise
        except Exception as e:
            raise AuthenticationFailed(f'Authentication error: {str(e)}')
    
    def get_auth_header(self, request):
        """Get the authorization header from request."""
        return request.META.get('HTTP_AUTHORIZATION', '')
    
    def get_token_from_header(self, auth_header):
        """Extract token from authorization header."""
        parts = auth_header.split()
        
        if len(parts) != 2:
            return None
        
        if parts[0].lower() != self.keyword.lower():
            return None
        
        return parts[1]
    
    def authenticate_token(self, token_string, request):
        """Authenticate the token."""
        try:
            # Find the token in database
            api_token = APIToken.objects.select_related('token_user').get(
                token=token_string,
                token_type='access',
                is_active=True
            )
            
            # Check if token is valid
            if not api_token.is_valid():
                raise AuthenticationFailed('Token is expired, revoked, or user is inactive')
            
            # Update token usage
            ip_address = get_client_ip(request)
            user_agent = get_user_agent(request)
            api_token.use_token(ip_address, user_agent)
            
            # Return token user and token
            return (api_token.token_user, api_token)
            
        except APIToken.DoesNotExist:
            raise AuthenticationFailed('Invalid token')
    
    def authenticate_header(self, request):
        """Return the authentication header for 401 responses."""
        return f'{self.keyword} realm="api"'
