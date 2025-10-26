"""
Web app views for API management and authentication.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login as django_login
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.db import transaction
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from authentication.models import TokenUser, APIToken, APIEndpoint, TokenPermission
from .log_parser import LogParser, get_available_logs
import requests
import secrets
import logging
import psutil
import time
import os

logger = logging.getLogger(__name__)


def check_staff_permission(request):
    """
    Check if the authenticated user has staff or superuser permissions.
    Returns tuple: (is_authorized, redirect_response)
    """
    if not request.session.get('authenticated'):
        return False, redirect('web:login')
    
    is_staff = request.session.get('is_staff', False)
    is_superuser = request.session.get('is_superuser', False)
    
    if not (is_staff or is_superuser):
        username = request.session.get('username', 'Unknown')
        logger.warning(f"Unauthorized access attempt by {username}")
        messages.error(request, 'Access denied. Insufficient permissions.')
        return False, redirect('web:login')
    
    return True, None


def login_view(request):
    """Display login page with WSO2 SSO option or handle local login."""
    # If user is already authenticated, redirect to dashboard
    if request.session.get('authenticated'):
        return redirect('web:dashboard')
    
    # Handle POST request for local login
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            messages.error(request, 'Please provide both username and password.')
            return redirect('web:login')
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        
        if user is not None and user.is_active:
            # Check if user is staff or superuser
            if not (user.is_staff or user.is_superuser):
                logger.warning(f"Non-staff user {username} attempted to access web application")
                messages.error(request, 'Access denied. Only staff members and administrators can access this application.')
                return redirect('web:login')
            
            # Store user info in session
            request.session['authenticated'] = True
            request.session['user_email'] = user.email or f'{user.username}@seu.edu.sa'
            request.session['user_name'] = user.get_full_name() or user.username
            request.session['username'] = user.username
            request.session['is_staff'] = user.is_staff
            request.session['is_superuser'] = user.is_superuser
            
            logger.info(f"User {username} authenticated successfully via local login")
            messages.success(request, f"Welcome, {request.session['user_name']}!")
            
            return redirect('web:dashboard')
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            messages.error(request, 'Invalid username or password.')
            return redirect('web:login')
    
    # Handle GET request - display login form
    context = {
        'page_title': 'Login - SEU API Management',
        'sso_enabled': getattr(settings, 'WSO2_SSO_ENABLED', False),
    }
    return render(request, 'web/login.html', context)


def sso_login(request):
    """Initiate WSO2 SSO login flow."""
    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    
    # Build authorization URL
    auth_params = {
        'response_type': 'code',
        'client_id': settings.WSO2_CLIENT_ID,
        'redirect_uri': settings.WSO2_REDIRECT_URI,
        'scope': settings.WSO2_SCOPE,
        'state': state,
    }
    
    auth_url = f"{settings.WSO2_AUTHORIZATION_URL}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"
    
    return HttpResponseRedirect(auth_url)


def sso_callback(request):
    """Handle WSO2 SSO callback."""
    # Get authorization code from callback
    code = request.GET.get('code')
    state = request.GET.get('state')
    error = request.GET.get('error')
    
    # Handle error from SSO provider
    if error:
        logger.error(f"SSO error: {error}")
        messages.error(request, f"SSO authentication failed: {error}")
        return redirect('web:login')
    
    # Verify state parameter
    if state != request.session.get('oauth_state'):
        logger.error("OAuth state mismatch")
        messages.error(request, "Invalid state parameter. Please try again.")
        return redirect('web:login')
    
    if not code:
        messages.error(request, "No authorization code received.")
        return redirect('web:login')
    
    try:
        # Exchange code for access token
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': settings.WSO2_REDIRECT_URI,
            'client_id': settings.WSO2_CLIENT_ID,
            'client_secret': settings.WSO2_CLIENT_SECRET,
        }
        
        token_response = requests.post(
            settings.WSO2_TOKEN_URL,
            data=token_data,
            timeout=10
        )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            messages.error(request, "Failed to obtain access token.")
            return redirect('web:login')
        
        token_json = token_response.json()
        access_token = token_json.get('access_token')
        
        # Get user info from WSO2
        userinfo_response = requests.get(
            settings.WSO2_USERINFO_URL,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        
        if userinfo_response.status_code != 200:
            logger.error(f"Userinfo request failed: {userinfo_response.text}")
            messages.error(request, "Failed to get user information.")
            return redirect('web:login')
        
        userinfo = userinfo_response.json()
        user_email = userinfo.get('email', '')
        user_name = userinfo.get('name', userinfo.get('preferred_username', ''))
        
        # Check if user exists in Django and has staff/superuser permissions
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            # Try to find user by email or username
            django_user = None
            if user_email:
                django_user = User.objects.filter(email=user_email).first()
            
            if not django_user:
                # Try by username (if username is provided in userinfo)
                username = userinfo.get('preferred_username', '')
                if username:
                    django_user = User.objects.filter(username=username).first()
            
            # Check if user has required permissions
            if not django_user or not django_user.is_active:
                logger.warning(f"SSO user {user_email} not found in Django or inactive")
                messages.error(request, 'Access denied. Your account is not authorized for this application.')
                return redirect('web:login')
            
            if not (django_user.is_staff or django_user.is_superuser):
                logger.warning(f"Non-staff SSO user {user_email} attempted to access web application")
                messages.error(request, 'Access denied. Only staff members and administrators can access this application.')
                return redirect('web:login')
            
            # Store user info in session
            request.session['authenticated'] = True
            request.session['user_email'] = user_email
            request.session['user_name'] = user_name
            request.session['username'] = django_user.username
            request.session['is_staff'] = django_user.is_staff
            request.session['is_superuser'] = django_user.is_superuser
            request.session['access_token'] = access_token
            
            logger.info(f"SSO user {user_email} authenticated successfully")
            messages.success(request, f"Welcome, {user_name}!")
            
            return redirect('web:dashboard')
            
        except Exception as user_check_error:
            logger.error(f"Error checking user permissions: {str(user_check_error)}")
            messages.error(request, 'Access denied. Unable to verify your permissions.')
            return redirect('web:login')
        
    except requests.RequestException as e:
        logger.error(f"SSO request error: {str(e)}")
        messages.error(request, "SSO authentication failed. Please try again.")
        return redirect('web:login')
    except Exception as e:
        logger.error(f"SSO authentication error: {str(e)}")
        messages.error(request, "An unexpected error occurred during authentication.")
        return redirect('web:login')


def logout_view(request):
    """Logout user and clear session."""
    user_name = request.session.get('user_name', 'User')
    
    # Clear session
    request.session.flush()
    
    messages.success(request, f"Goodbye, {user_name}! You have been logged out.")
    return redirect('web:login')


def dashboard_view(request):
    """Main dashboard for authenticated users."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    context = {
        'page_title': 'Dashboard - SEU API Management',
        'user_name': request.session.get('user_name'),
        'user_email': request.session.get('user_email'),
    }
    return render(request, 'web/dashboard.html', context)


def system_metrics_view(request):
    """Return system metrics as JSON for live monitoring."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # Memory metrics
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024 ** 3)  # Convert to GB
        memory_total_gb = memory.total / (1024 ** 3)
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        disk_used_gb = disk.used / (1024 ** 3)
        disk_total_gb = disk.total / (1024 ** 3)
        
        # Network metrics
        net_io = psutil.net_io_counters()
        bytes_sent_mb = net_io.bytes_sent / (1024 ** 2)  # Convert to MB
        bytes_recv_mb = net_io.bytes_recv / (1024 ** 2)
        
        # Process count
        process_count = len(psutil.pids())
        
        # Boot time
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_hours = uptime_seconds / 3600
        
        metrics = {
            'timestamp': time.time(),
            'cpu': {
                'percent': round(cpu_percent, 2),
                'count': cpu_count,
                'frequency': round(cpu_freq.current, 2) if cpu_freq else 0,
            },
            'memory': {
                'percent': round(memory_percent, 2),
                'used_gb': round(memory_used_gb, 2),
                'total_gb': round(memory_total_gb, 2),
                'available_gb': round(memory.available / (1024 ** 3), 2),
            },
            'disk': {
                'percent': round(disk_percent, 2),
                'used_gb': round(disk_used_gb, 2),
                'total_gb': round(disk_total_gb, 2),
                'free_gb': round(disk.free / (1024 ** 3), 2),
            },
            'network': {
                'bytes_sent_mb': round(bytes_sent_mb, 2),
                'bytes_recv_mb': round(bytes_recv_mb, 2),
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
            },
            'system': {
                'process_count': process_count,
                'uptime_hours': round(uptime_hours, 2),
            }
        }
        
        return JsonResponse(metrics)
        
    except Exception as e:
        logger.error(f"Error fetching system metrics: {str(e)}")
        return JsonResponse({'error': 'Failed to fetch metrics'}, status=500)


# ==================== Token Management Views ====================

def tokens_list_view(request):
    """List all application tokens."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    # Get all token users with their associated information
    token_users = TokenUser.objects.all().prefetch_related('tokens', 'endpoint_permissions__endpoint')
    
    # Prepare token data with permissions count
    tokens_data = []
    for token_user in token_users:
        active_token = token_user.tokens.filter(is_active=True, token_type='access').first()
        tokens_data.append({
            'id': token_user.id,
            'name': token_user.name,
            'email': token_user.email,
            'is_active': token_user.is_active,
            'has_active_token': active_token is not None,
            'token_key': active_token.token[:20] + '...' if active_token else 'No active token',
            'full_token': active_token.token if active_token else '',  # Full token for copying
            'permissions_count': token_user.endpoint_permissions.count(),
            'created_at': token_user.created_at,
        })
    
    context = {
        'page_title': 'Application Tokens - SEU API Management',
        'tokens': tokens_data,
    }
    return render(request, 'web/tokens_list.html', context)


def token_create_view(request):
    """Create a new application token."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip()
        company = request.POST.get('company', '').strip()
        notes = request.POST.get('notes', '').strip()
        access_lifetime = request.POST.get('access_token_lifetime_hours', '24')
        refresh_lifetime = request.POST.get('refresh_token_lifetime_days', '30')
        
        # Validate inputs
        if not name:
            messages.error(request, 'Application name is required.')
            return redirect('web:token_create')
        
        if not email:
            messages.error(request, 'Email is required.')
            return redirect('web:token_create')
        
        # Validate token lifetimes
        try:
            access_lifetime = int(access_lifetime)
            refresh_lifetime = int(refresh_lifetime)
            
            if access_lifetime < 1 or access_lifetime > 8760:  # Max 1 year
                messages.error(request, 'Access token lifetime must be between 1 and 8760 hours.')
                return redirect('web:token_create')
            
            if refresh_lifetime < 1 or refresh_lifetime > 365:  # Max 1 year
                messages.error(request, 'Refresh token lifetime must be between 1 and 365 days.')
                return redirect('web:token_create')
                
        except ValueError:
            messages.error(request, 'Token lifetime values must be valid numbers.')
            return redirect('web:token_create')
        
        try:
            # Create token user and generate token
            with transaction.atomic():
                # Create TokenUser
                token_user = TokenUser.objects.create(
                    name=name,
                    email=email,
                    company=company,
                    notes=notes,
                    access_token_lifetime_hours=access_lifetime,
                    refresh_token_lifetime_days=refresh_lifetime,
                    is_active=True,
                    created_by=request.session.get('username', 'admin')
                )
                
                # Generate API tokens (access and refresh)
                tokens_data = token_user.create_tokens()
                
                logger.info(
                    f"Created new token for application: {name} (Company: {company or 'N/A'}) "
                    f"with access lifetime {access_lifetime}h and refresh lifetime {refresh_lifetime}d "
                    f"(by {request.session.get('username', 'unknown')})"
                )
                
                # Store token in session to display on next page
                request.session['new_access_token'] = tokens_data['access_token']
                request.session['new_refresh_token'] = tokens_data['refresh_token']
                request.session['token_expires_at'] = tokens_data['access_expires_at'].strftime('%Y-%m-%d %H:%M:%S')
                
                messages.success(
                    request, 
                    f"Token created successfully for {name}!"
                )
                
                return redirect('web:token_permissions', token_id=token_user.id)
                
        except Exception as e:
            logger.error(f"Error creating token: {str(e)}")
            messages.error(request, f"Failed to create token: {str(e)}")
            return redirect('web:token_create')
    
    # GET request - show form
    context = {
        'page_title': 'Create New Token - SEU API Management',
    }
    return render(request, 'web/token_create.html', context)


def token_permissions_view(request, token_id):
    """Manage endpoint permissions for a token."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    token_user = get_object_or_404(TokenUser, id=token_id)
    
    if request.method == 'POST':
        # Handle permission grant/revoke
        action = request.POST.get('action')
        endpoint_ids = request.POST.getlist('endpoint_ids')
        
        if action == 'grant' and endpoint_ids:
            try:
                with transaction.atomic():
                    granted_count = 0
                    for endpoint_id in endpoint_ids:
                        endpoint = APIEndpoint.objects.get(id=endpoint_id)
                        # Check if permission already exists
                        permission, created = TokenPermission.objects.get_or_create(
                            token_user=token_user,
                            endpoint=endpoint,
                            defaults={
                                'granted_by': request.session.get('username', 'admin'),
                                'notes': f'Granted via web interface'
                            }
                        )
                        if created:
                            granted_count += 1
                    
                    if granted_count > 0:
                        logger.info(
                            f"Granted {granted_count} endpoint permissions to {token_user.name} "
                            f"(by {request.session.get('username', 'unknown')})"
                        )
                        messages.success(request, f"Successfully granted access to {granted_count} endpoint(s).")
                    else:
                        messages.info(request, "Selected endpoints already have access granted.")
                        
            except Exception as e:
                logger.error(f"Error granting permissions: {str(e)}")
                messages.error(request, f"Failed to grant permissions: {str(e)}")
        
        elif action == 'revoke' and endpoint_ids:
            try:
                with transaction.atomic():
                    revoked_count = TokenPermission.objects.filter(
                        token_user=token_user,
                        endpoint_id__in=endpoint_ids
                    ).delete()[0]
                    
                    if revoked_count > 0:
                        logger.info(
                            f"Revoked {revoked_count} endpoint permissions from {token_user.name} "
                            f"(by {request.session.get('username', 'unknown')})"
                        )
                        messages.success(request, f"Successfully revoked access to {revoked_count} endpoint(s).")
                    else:
                        messages.info(request, "No permissions were revoked.")
                        
            except Exception as e:
                logger.error(f"Error revoking permissions: {str(e)}")
                messages.error(request, f"Failed to revoke permissions: {str(e)}")
        
        return redirect('web:token_permissions', token_id=token_id)
    
    # GET request - show permissions management page
    # Get all endpoints grouped by category
    all_endpoints = APIEndpoint.objects.filter(is_active=True).order_by('category', 'name')
    
    # Get currently granted permissions
    granted_permissions = TokenPermission.objects.filter(token_user=token_user).select_related('endpoint')
    granted_endpoint_ids = set(granted_permissions.values_list('endpoint_id', flat=True))
    
    # Group endpoints by category
    endpoints_by_category = {}
    for endpoint in all_endpoints:
        category = endpoint.get_category_display()
        if category not in endpoints_by_category:
            endpoints_by_category[category] = []
        endpoints_by_category[category].append({
            'id': endpoint.id,
            'name': endpoint.name,
            'url_pattern': endpoint.url_pattern,
            'description': endpoint.description,
            'has_access': endpoint.id in granted_endpoint_ids,
        })
    
    # Get active access token
    active_token = token_user.tokens.filter(is_active=True, token_type='access').first()
    
    context = {
        'page_title': f'Manage Permissions - {token_user.name}',
        'token_user': token_user,
        'active_token': active_token,
        'endpoints_by_category': endpoints_by_category,
        'granted_permissions': granted_permissions,
        'total_endpoints': all_endpoints.count(),
        'granted_count': len(granted_endpoint_ids),
    }
    
    # Render the response
    response = render(request, 'web/token_permissions.html', context)
    
    # Clear session tokens after displaying them (security measure)
    if 'new_access_token' in request.session:
        del request.session['new_access_token']
    if 'new_refresh_token' in request.session:
        del request.session['new_refresh_token']
    if 'token_expires_at' in request.session:
        del request.session['token_expires_at']
    
    return response


def token_revoke_view(request, token_id):
    """Revoke/deactivate a token."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    token_user = get_object_or_404(TokenUser, id=token_id)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Deactivate the token user
                token_user.is_active = False
                token_user.save()
                
                # Deactivate all associated tokens
                token_user.tokens.update(is_active=False)
                
                logger.info(
                    f"Revoked token for {token_user.name} "
                    f"(by {request.session.get('username', 'unknown')})"
                )
                messages.success(request, f"Successfully revoked token for {token_user.name}.")
                
        except Exception as e:
            logger.error(f"Error revoking token: {str(e)}")
            messages.error(request, f"Failed to revoke token: {str(e)}")
    
    return redirect('web:tokens_list')


def token_activate_view(request, token_id):
    """Activate/reactivate a token."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    token_user = get_object_or_404(TokenUser, id=token_id)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Activate the token user
                token_user.is_active = True
                token_user.save()
                
                # Activate all associated tokens
                token_user.tokens.update(is_active=True)
                
                logger.info(
                    f"Activated token for {token_user.name} "
                    f"(by {request.session.get('username', 'unknown')})"
                )
                messages.success(request, f"Successfully activated token for {token_user.name}.")
                
        except Exception as e:
            logger.error(f"Error activating token: {str(e)}")
            messages.error(request, f"Failed to activate token: {str(e)}")
    
    return redirect('web:tokens_list')


def token_refresh_view(request, token_id):
    """Refresh/regenerate tokens for a token user."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    token_user = get_object_or_404(TokenUser, id=token_id)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Deactivate old tokens
                token_user.tokens.update(is_active=False)
                
                # Generate new tokens
                tokens_data = token_user.create_tokens()
                
                # Store new tokens in session to display
                request.session['new_access_token'] = tokens_data['access_token']
                request.session['new_refresh_token'] = tokens_data['refresh_token']
                request.session['token_expires_at'] = tokens_data['access_expires_at'].strftime('%Y-%m-%d %H:%M:%S')
                
                logger.info(
                    f"Refreshed tokens for {token_user.name} "
                    f"(by {request.session.get('username', 'unknown')})"
                )
                messages.success(
                    request, 
                    f"Successfully refreshed tokens for {token_user.name}. New tokens are displayed below."
                )
                
                return redirect('web:token_permissions', token_id=token_user.id)
                
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            messages.error(request, f"Failed to refresh token: {str(e)}")
    
    return redirect('web:tokens_list')


def logs_viewer_view(request):
    """View and search through API request logs."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    # Get available log files
    available_logs = get_available_logs()
    
    # Get selected log file (default to APIM.log)
    selected_log = request.GET.get('log_file', 'APIM.log')
    log_path = os.path.join(settings.BASE_DIR, 'logs', selected_log)
    
    # Get filter parameters
    search_query = request.GET.get('search', '').strip()
    method_filter = request.GET.get('method', '').strip()
    status_filter = request.GET.get('status', '').strip()
    level_filter = request.GET.get('level', '').strip()
    start_date = request.GET.get('start_date', '').strip()
    end_date = request.GET.get('end_date', '').strip()
    
    # Default "HTTP Requests Only" to false for app.log and errors.log, true for api.log
    default_show_requests = 'true' if selected_log == 'api.log' else 'false'
    show_only_requests = request.GET.get('show_only_requests', default_show_requests) == 'true'
    
    # Parse log file
    parser = LogParser(log_path)
    max_lines = 2000  # Limit to prevent memory issues
    entries = parser.parse_file(max_lines=max_lines, reverse=True)
    
    # Filter to show only HTTP requests if requested
    if show_only_requests:
        entries = [e for e in entries if e.is_http_request()]
    
    # Apply filters
    if any([search_query, method_filter, status_filter, level_filter, start_date, end_date]):
        entries = parser.filter_entries(
            entries,
            search=search_query,
            method=method_filter if method_filter else None,
            status_code=status_filter if status_filter else None,
            level=level_filter if level_filter else None,
            start_date=start_date if start_date else None,
            end_date=end_date if end_date else None
        )
    
    # Pagination
    page = request.GET.get('page', 1)
    paginator = Paginator(entries, 50)  # 50 entries per page
    
    try:
        paginated_entries = paginator.page(page)
    except PageNotAnInteger:
        paginated_entries = paginator.page(1)
    except EmptyPage:
        paginated_entries = paginator.page(paginator.num_pages)
    
    # Get unique values for filters
    unique_methods = sorted(set(e.method for e in entries if e.method))
    unique_status_codes = sorted(set(e.status_code for e in entries if e.status_code))
    unique_levels = sorted(set(e.level for e in entries if e.level))
    
    context = {
        'page_title': 'Request Logs - SEU API Management',
        'entries': paginated_entries,
        'available_logs': available_logs,
        'selected_log': selected_log,
        'search_query': search_query,
        'method_filter': method_filter,
        'status_filter': status_filter,
        'level_filter': level_filter,
        'start_date': start_date,
        'end_date': end_date,
        'show_only_requests': show_only_requests,
        'unique_methods': unique_methods,
        'unique_status_codes': unique_status_codes,
        'unique_levels': unique_levels,
        'total_entries': len(entries),
    }
    
    return render(request, 'web/logs_viewer.html', context)


def token_detail_view(request, token_id):
    """View and edit application token details."""
    # Check if user is authenticated and has staff permissions
    is_authorized, redirect_response = check_staff_permission(request)
    if not is_authorized:
        return redirect_response
    
    try:
        token_user = TokenUser.objects.get(id=token_id)
    except TokenUser.DoesNotExist:
        messages.error(request, 'Application token not found.')
        return redirect('web:tokens_list')
    
    # Handle POST request for editing
    if request.method == 'POST':
        token_user.name = request.POST.get('name', token_user.name)
        token_user.email = request.POST.get('email', token_user.email)
        token_user.company = request.POST.get('company', token_user.company)
        token_user.notes = request.POST.get('notes', token_user.notes)
        token_user.save()
        
        messages.success(request, f'Application "{token_user.name}" updated successfully.')
        return redirect('web:token_detail', token_id=token_id)
    
    # Get active tokens
    access_token = token_user.tokens.filter(is_active=True, token_type='access').first()
    refresh_token = token_user.tokens.filter(is_active=True, token_type='refresh').first()
    
    # Get subscribed endpoints
    permissions = token_user.endpoint_permissions.select_related('endpoint').all()
    subscribed_endpoints = [
        {
            'name': perm.endpoint.name,
            'category': perm.endpoint.category,
            'url_pattern': perm.endpoint.url_pattern,
            'description': perm.endpoint.description,
            'granted_at': perm.granted_at,
        }
        for perm in permissions
    ]
    
    # Get recent API calls from logs (last 10)
    import os
    from datetime import datetime, timedelta
    recent_calls = []
    
    try:
        log_file = os.path.join(settings.BASE_DIR, 'logs', 'api.log')
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            # Parse last 50 lines to find calls from this app
            for line in reversed(lines[-50:]):
                if f'App: {token_user.name}' in line:
                    # Simple parsing - extract method, path, status, duration
                    try:
                        import re
                        match = re.search(r'"(\w+)\s+([^\s]+)\s+HTTP/[\d.]+"\s+(\d+).*Duration:\s+([\d.]+)s', line)
                        if match:
                            method, path, status, duration = match.groups()
                            recent_calls.append({
                                'method': method,
                                'path': path,
                                'status': int(status),
                                'duration': float(duration),
                            })
                            if len(recent_calls) >= 10:
                                break
                    except:
                        continue
    except Exception as e:
        print(f"Error reading logs: {e}")
    
    # Calculate statistics
    total_calls = len(recent_calls)
    failed_calls = len([c for c in recent_calls if c['status'] >= 400])
    avg_duration = sum([c['duration'] for c in recent_calls]) / total_calls if total_calls > 0 else 0
    
    context = {
        'page_title': f'{token_user.name} - Application Details',
        'token_user': token_user,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'subscribed_endpoints': subscribed_endpoints,
        'recent_calls': recent_calls,
        'stats': {
            'total_calls': total_calls,
            'failed_calls': failed_calls,
            'success_rate': ((total_calls - failed_calls) / total_calls * 100) if total_calls > 0 else 0,
            'avg_duration': avg_duration,
            'total_permissions': len(subscribed_endpoints),
        }
    }
    
    return render(request, 'web/token_detail.html', context)
