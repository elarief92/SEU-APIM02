"""
Custom permission classes for endpoint-level access control.
"""

from rest_framework.permissions import BasePermission
from .models import APIEndpoint
import logging

logger = logging.getLogger(__name__)


class HasEndpointPermission(BasePermission):
    """
    Custom permission to check if the authenticated token user has access to the requested endpoint.
    """
    
    message = "You don't have permission to access this endpoint."
    
    def has_permission(self, request, view):
        """
        Check if the user has permission to access this endpoint.
        """
        # If user is not authenticated, deny access
        if not request.user or not hasattr(request.user, 'is_authenticated'):
            return False
        
        if not request.user.is_authenticated:
            return False
        
        # Get the request path
        request_path = request.path.strip('/')
        
        # Try to find matching endpoint by URL pattern
        try:
            # Get all active endpoints (optimized with only needed fields)
            endpoints = APIEndpoint.objects.filter(is_active=True).only('id', 'url_pattern', 'name')
            
            # Find first endpoint whose URL pattern is contained in the request path
            matched_endpoint = None
            for endpoint in endpoints:
                endpoint_pattern = endpoint.url_pattern.strip('/')
                if endpoint_pattern in request_path:
                    matched_endpoint = endpoint
                    break
            
            if not matched_endpoint:
                # No endpoint found matching this URL
                logger.warning(
                    f"No endpoint definition found for path: {request_path} "
                    f"(User: {request.user})"
                )
                # Allow access if no endpoint is defined (backward compatibility)
                return True
            
            # Check if token user has permission for this endpoint
            has_permission = request.user.has_endpoint_permission(matched_endpoint.url_pattern)
            
            if not has_permission:
                logger.warning(
                    f"Permission denied - User: {request.user.name} ({request.user.email}) "
                    f"attempted to access: {matched_endpoint.name} ({matched_endpoint.url_pattern})"
                )
                self.message = f"You don't have permission to access '{matched_endpoint.name}'. Please contact your administrator."
            else:
                logger.info(
                    f"Permission granted - User: {request.user.name} "
                    f"accessing: {matched_endpoint.name}"
                )
            
            return has_permission
            
        except Exception as e:
            logger.error(f"Error checking endpoint permission: {str(e)}")
            # On error, deny access for security
            return False

