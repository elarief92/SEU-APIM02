"""
Custom exception handler for DRF to ensure proper error logging.
"""
from rest_framework.views import exception_handler as drf_exception_handler
import logging
import traceback

logger = logging.getLogger('apis')


def custom_exception_handler(exc, context):
    """
    Custom exception handler that logs all errors with full tracebacks.
    """
    # Get the standard DRF response
    response = drf_exception_handler(exc, context)
    
    # Get request details
    request = context.get('request')
    view = context.get('view')
    
    # Build detailed error message
    error_details = []
    error_details.append(f"Exception: {exc.__class__.__name__}")
    error_details.append(f"Message: {str(exc)}")
    
    if request:
        error_details.append(f"Method: {request.method}")
        error_details.append(f"Path: {request.path}")
        
        # Get application name if available
        if hasattr(request, 'user') and hasattr(request.user, 'name'):
            error_details.append(f"Application: {request.user.name}")
        elif hasattr(request, 'user') and hasattr(request.user, 'username'):
            error_details.append(f"User: {request.user.username}")
    
    if view:
        error_details.append(f"View: {view.__class__.__name__}")
    
    # Log the error with traceback
    error_message = " | ".join(error_details)
    
    if response is None:
        # Unhandled exception - log as error with traceback
        logger.error(error_message, exc_info=True)
    else:
        # Handled exception - log based on status code
        if response.status_code >= 500:
            logger.error(error_message, exc_info=True)
        elif response.status_code >= 400:
            logger.warning(error_message)
        else:
            logger.info(error_message)
    
    return response

