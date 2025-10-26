# WSO2 SSO Integration Setup Guide

## Overview

This guide will help you configure WSO2 Single Sign-On (SSO) integration for the SEU API Management portal using OAuth2/OpenID Connect.

## Features

- ✅ Modern, responsive login page
- ✅ WSO2 OAuth2/OpenID Connect integration
- ✅ Session management
- ✅ User dashboard
- ✅ Secure token handling

## Prerequisites

1. WSO2 Identity Server installed and running
2. Access to WSO2 Admin Console
3. Python 3.8+ environment
4. Django project running

## Step 1: Configure WSO2 Identity Server

### 1.1 Create Service Provider in WSO2

1. Log in to WSO2 Identity Server Management Console
   - URL: `https://your-wso2-server:9443/carbon`
   
2. Navigate to **Main > Identity > Service Providers > Add**

3. Create a new Service Provider:
   - **Service Provider Name**: `SEU_API_Management`
   - Click **Register**

4. Configure OAuth/OpenID Connect:
   - Expand **Inbound Authentication Configuration**
   - Click **OAuth/OpenID Connect Configuration > Configure**
   
5. Set OAuth Configuration:
   - **Callback URL**: `http://localhost:8000/apim/web/sso/callback/` (adjust for production)
   - **Allowed Grant Types**: Check `Authorization Code`
   - Click **Add** to save

6. Save the following details (you'll need them later):
   - **OAuth Client Key** (Client ID)
   - **OAuth Client Secret**

### 1.2 Configure Claims

1. Go to **Main > Identity > Claims > Add**
2. Ensure the following claims are mapped:
   - `email`
   - `name` or `preferred_username`
   - `profile`

## Step 2: Configure Django Application

### 2.1 Install Required Packages

```bash
cd /Users/zshaikh/Documents/projects/SEU_dev/seu_apim
source venv/bin/activate
pip install -r requirements.txt
```

### 2.2 Configure Environment Variables

1. Create or update your `.env` file (use `env_template.txt` as reference):

```bash
# WSO2 SSO Configuration
WSO2_SSO_ENABLED=True
WSO2_CLIENT_ID=your_oauth_client_key_from_wso2
WSO2_CLIENT_SECRET=your_oauth_client_secret_from_wso2
WSO2_AUTHORIZATION_URL=https://your-wso2-server.com:9443/oauth2/authorize
WSO2_TOKEN_URL=https://your-wso2-server.com:9443/oauth2/token
WSO2_USERINFO_URL=https://your-wso2-server.com:9443/oauth2/userinfo
WSO2_REDIRECT_URI=http://localhost:8000/apim/web/sso/callback/
WSO2_SCOPE=openid profile email
```

### 2.3 Important URLs to Configure

Replace `your-wso2-server.com` with your actual WSO2 server address.

**Common WSO2 URLs:**

- **WSO2 IS 5.x/6.x**:
  - Authorization: `https://your-server:9443/oauth2/authorize`
  - Token: `https://your-server:9443/oauth2/token`
  - UserInfo: `https://your-server:9443/oauth2/userinfo`

- **WSO2 IS with Custom Context Path**:
  - Check your WSO2 deployment for custom paths

## Step 3: Run Migrations and Start Server

```bash
# Run migrations (if needed)
./venv/bin/python manage.py migrate

# Start development server
./venv/bin/python manage.py runserver
```

## Step 4: Test SSO Integration

1. Navigate to: `http://localhost:8000/apim/web/login/`

2. Click **"Sign in with WSO2 SSO"** button

3. You should be redirected to WSO2 login page

4. Enter your WSO2 credentials

5. After successful authentication, you'll be redirected to the dashboard

## URL Structure

| Route | Purpose |
|-------|---------|
| `/apim/web/` | Login page |
| `/apim/web/login/` | Login page |
| `/apim/web/sso/login/` | Initiate SSO flow |
| `/apim/web/sso/callback/` | SSO callback handler |
| `/apim/web/dashboard/` | User dashboard |
| `/apim/web/logout/` | Logout and clear session |

## Security Considerations

### Production Deployment

1. **Use HTTPS**: Always use HTTPS in production
   ```bash
   WSO2_REDIRECT_URI=https://your-domain.com/apim/web/sso/callback/
   ```

2. **Secure Secret Key**: Generate a strong secret key
   ```bash
   SECRET_KEY=your-very-secure-secret-key
   ```

3. **Update Allowed Hosts**:
   ```bash
   ALLOWED_HOSTS=your-domain.com,www.your-domain.com
   ```

4. **Enable DEBUG=False**:
   ```bash
   DEBUG=False
   ```

## Troubleshooting

### Common Issues

#### 1. "Invalid Redirect URI" Error

**Problem**: WSO2 rejects the redirect URI

**Solution**: 
- Ensure the callback URL in WSO2 Service Provider matches exactly
- Include protocol (http/https), domain, port, and path
- No trailing slash mismatch

#### 2. "Invalid State Parameter" Error

**Problem**: State verification fails

**Solution**:
- Ensure sessions are properly configured
- Check that `django.contrib.sessions` is in INSTALLED_APPS
- Verify session middleware is active

#### 3. SSL Certificate Errors

**Problem**: SSL verification fails

**Solution** (for development only):
```python
# In views.py, add verify=False for development
token_response = requests.post(
    settings.WSO2_TOKEN_URL,
    data=token_data,
    verify=False,  # Only for development!
    timeout=10
)
```

**Note**: Never disable SSL verification in production!

#### 4. "Failed to Get User Information"

**Problem**: UserInfo endpoint returns error

**Solution**:
- Verify the access token is valid
- Check WSO2 claim configuration
- Ensure required scopes are requested

## Testing Without WSO2

If WSO2 is not yet configured, you can test the interface:

1. Set `WSO2_SSO_ENABLED=False` in `.env`
2. The login page will show a local login form
3. You can develop the UI and other features

## Logging

The application logs SSO-related events. Check logs for debugging:

```bash
tail -f logs/APIM.log
```

## Next Steps

After successful SSO integration:

1. ✅ Implement token management views
2. ✅ Add API token generation for authenticated users
3. ✅ Create user profile pages
4. ✅ Add role-based access control
5. ✅ Implement API usage statistics

## Support

For issues specific to:
- **WSO2 Configuration**: Check WSO2 Identity Server documentation
- **Django Integration**: Review the code in `web/views.py`
- **OAuth Flow**: Refer to OAuth 2.0 and OpenID Connect specifications

## Additional Resources

- [WSO2 Identity Server Documentation](https://is.docs.wso2.com/)
- [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)

