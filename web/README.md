# Web App - API Management Interface

## Overview

This Django app provides a web interface for managing API access, including token creation and management through WSO2 SSO authentication.

## Structure

```
web/
├── __init__.py
├── admin.py
├── apps.py
├── models.py
├── views.py          # Login, SSO callback, dashboard views
├── urls.py           # URL routing
├── tests.py
└── README.md
```

## Views

### Authentication Views

- **`login_view`**: Display login page with SSO option
- **`sso_login`**: Initiate OAuth2 flow with WSO2
- **`sso_callback`**: Handle OAuth2 callback and user authentication
- **`logout_view`**: Clear session and logout user

### Dashboard Views

- **`dashboard_view`**: Main dashboard for authenticated users

## URL Patterns

| Pattern | View | Name | Description |
|---------|------|------|-------------|
| `` | `login_view` | `login` | Login page |
| `login/` | `login_view` | `login` | Login page (explicit) |
| `logout/` | `logout_view` | `logout` | Logout endpoint |
| `sso/login/` | `sso_login` | `sso_login` | Initiate SSO |
| `sso/callback/` | `sso_callback` | `sso_callback` | SSO callback |
| `dashboard/` | `dashboard_view` | `dashboard` | User dashboard |

## Templates

### Template Structure

```
templates/web/
├── base.html          # Base template with Bootstrap 5
├── login.html         # Login page with SSO button
└── dashboard.html     # User dashboard
```

### Template Features

- **Responsive Design**: Mobile-friendly Bootstrap 5
- **Modern UI**: Gradient backgrounds, cards, icons
- **Message System**: Django messages integration
- **SSO Toggle**: Shows SSO or local login based on configuration

## Configuration

### Required Settings

Add to `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'web',
]
```

### Required Environment Variables

```bash
WSO2_SSO_ENABLED=True
WSO2_CLIENT_ID=your_client_id
WSO2_CLIENT_SECRET=your_client_secret
WSO2_AUTHORIZATION_URL=https://wso2-server.com/oauth2/authorize
WSO2_TOKEN_URL=https://wso2-server.com/oauth2/token
WSO2_USERINFO_URL=https://wso2-server.com/oauth2/userinfo
WSO2_REDIRECT_URI=http://localhost:8000/apim/web/sso/callback/
WSO2_SCOPE=openid profile email
```

## Session Management

The app uses Django sessions to store:
- `authenticated`: Boolean flag
- `user_email`: User's email from SSO
- `user_name`: User's display name
- `access_token`: OAuth access token
- `oauth_state`: CSRF protection state

## Security Features

1. **State Parameter**: CSRF protection for OAuth flow
2. **Session Management**: Secure session handling
3. **Token Validation**: Verify tokens before granting access
4. **HTTPS Ready**: Designed for production HTTPS deployment

## Usage

### Access the Login Page

```
http://localhost:8000/apim/web/
```

### SSO Flow

1. User clicks "Sign in with WSO2 SSO"
2. Redirected to WSO2 login page
3. User authenticates with WSO2
4. WSO2 redirects back with authorization code
5. App exchanges code for access token
6. App retrieves user info
7. User session created
8. Redirected to dashboard

## Development

### Running Locally

```bash
# Activate virtual environment
source venv/bin/activate

# Run migrations
python manage.py migrate

# Start server
python manage.py runserver

# Access at http://localhost:8000/apim/web/
```

### Testing Without SSO

Set `WSO2_SSO_ENABLED=False` to test the interface without SSO configured.

## Next Features to Implement

1. Token Management
   - View all API tokens
   - Create new tokens
   - Revoke tokens
   - Token usage statistics

2. User Profile
   - View user details
   - Edit preferences
   - Change settings

3. API Documentation
   - Integrate with API docs
   - Show available endpoints
   - Interactive API testing

4. Analytics Dashboard
   - API usage graphs
   - Request statistics
   - Error tracking

## Dependencies

- Django 5.2+
- requests (for OAuth HTTP calls)
- Bootstrap 5 (CDN)
- Bootstrap Icons (CDN)

## See Also

- [WSO2_SSO_SETUP.md](../WSO2_SSO_SETUP.md) - Detailed SSO setup guide
- [APIM Settings](../APIM/settings.py) - Django settings
- [Main URLs](../APIM/urls.py) - URL configuration

