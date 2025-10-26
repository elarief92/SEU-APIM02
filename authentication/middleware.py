"""
Middleware for logging API requests with application names.
"""
import logging
import time

logger = logging.getLogger('apis')


class APIRequestLoggingMiddleware:
    """
    Middleware to log API requests with application name (TokenUser).
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Only log API requests (not web interface requests)
        if not request.path.startswith('/api/'):
            return self.get_response(request)
        
        # Record start time
        start_time = time.time()
        
        # Process the request
        response = self.get_response(request)
        
        # Calculate request duration
        duration = time.time() - start_time
        
        # Get application name if authenticated (after request processing)
        app_name = None
        if hasattr(request, 'user') and request.user:
            if hasattr(request.user, 'name'):
                # DRF TokenUser authentication
                app_name = request.user.name
            elif hasattr(request.user, 'username') and request.user.is_authenticated:
                # Django user authentication
                app_name = request.user.username
        
        # Build log message
        method = request.method
        path = request.path
        status_code = response.status_code
        
        # Only log failed requests (4xx and 5xx errors)
        if status_code >= 400:
            # Format: "METHOD /path HTTP/1.1" status_code response_size | App: application_name | Duration: X.XXs
            log_message = f'"{method} {path} HTTP/1.1" {status_code} {len(response.content)}'
            
            if app_name:
                log_message += f' | App: {app_name}'
            else:
                log_message += ' | App: Unauthenticated'
            
            log_message += f' | Duration: {duration:.3f}s'
            
            # Try to extract error message from response body
            try:
                import json
                if response.get('Content-Type', '').startswith('application/json'):
                    body = json.loads(response.content.decode('utf-8'))
                    # Look for common error message keys
                    error_msg = body.get('detail') or body.get('error') or body.get('message')
                    if error_msg:
                        log_message += f' | Error: {error_msg}'
            except:
                pass
            
            # Log with appropriate level based on status code
            if 400 <= status_code < 500:
                logger.warning(log_message)
            else:
                logger.error(log_message)
        
        return response

