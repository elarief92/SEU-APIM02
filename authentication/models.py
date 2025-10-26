from django.db import models
from django.utils import timezone
from datetime import timedelta
import secrets
import uuid


class APIEndpoint(models.Model):
    """Represents an API endpoint that can be accessed."""
    
    # Endpoint identification
    name = models.CharField(max_length=100, unique=True, help_text="Display name (e.g., 'Noor API')")
    url_pattern = models.CharField(max_length=200, help_text="URL pattern (e.g., 'api/v1/noor/')")
    description = models.TextField(blank=True, help_text="What this endpoint does")
    
    # Categorization
    CATEGORY_CHOICES = [
        ('student_services', 'Student Services'),
        ('verification', 'Verification Services'),
        ('erp', 'ERP Integration'),
        ('banner', 'Banner Database'),
        ('utilities', 'Utilities'),
        ('other', 'Other'),
    ]
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='other')
    
    # Status
    is_active = models.BooleanField(default=True, help_text="Is this endpoint available")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'api_endpoints'
        verbose_name = 'API Endpoint'
        verbose_name_plural = 'API Endpoints'
        ordering = ['category', 'name']
        indexes = [
            models.Index(fields=['url_pattern']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.category})"


class TokenUser(models.Model):
    """Simple token-based user representation."""
    
    # Basic identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, help_text="Customer/Client name")
    email = models.EmailField(blank=True, help_text="Contact email")
    company = models.CharField(max_length=200, blank=True, help_text="Company/Organization")
    
    # Token settings
    is_active = models.BooleanField(default=True, help_text="Can access APIs")
    access_token_lifetime_hours = models.IntegerField(default=24, help_text="Access token lifetime in hours")
    refresh_token_lifetime_days = models.IntegerField(default=30, help_text="Refresh token lifetime in days")
    
    # Permissions
    allowed_endpoints = models.ManyToManyField(
        'APIEndpoint', 
        through='TokenPermission',
        related_name='token_users',
        blank=True,
        help_text="Endpoints this token user can access"
    )
    
    # Usage tracking
    last_access = models.DateTimeField(null=True, blank=True, help_text="Last API access")
    total_requests = models.PositiveIntegerField(default=0, help_text="Total API requests made")
    
    # Admin info
    created_by = models.CharField(max_length=100, help_text="Admin who created this token user")
    notes = models.TextField(blank=True, help_text="Admin notes about this client")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'token_users'
        verbose_name = 'Token User'
        verbose_name_plural = 'Token Users'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.company or 'No Company'})"
    
    def update_last_access(self):
        """Update last access time and increment request count."""
        self.last_access = timezone.now()
        self.total_requests += 1
        self.save(update_fields=['last_access', 'total_requests'])
    
    @property
    def is_authenticated(self):
        """Always return True for authenticated token users."""
        return True
    
    @property
    def is_anonymous(self):
        """Always return False for authenticated token users."""
        return False
    
    def create_tokens(self):
        """Create new access and refresh tokens for this user."""
        # Generate tokens
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        
        # Calculate expiry times
        access_expires = timezone.now() + timedelta(hours=self.access_token_lifetime_hours)
        refresh_expires = timezone.now() + timedelta(days=self.refresh_token_lifetime_days)
        
        # Create access token
        access_api_token = APIToken.objects.create(
            token_user=self,
            token=access_token,
            token_type='access',
            expires_at=access_expires,
            name=f"Access Token - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
        )
        
        # Create refresh token
        refresh_api_token = APIToken.objects.create(
            token_user=self,
            token=refresh_token,
            token_type='refresh',
            expires_at=refresh_expires,
            name=f"Refresh Token - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'access_expires_at': access_expires,
            'refresh_expires_at': refresh_expires,
            'expires_in': int(timedelta(hours=self.access_token_lifetime_hours).total_seconds())
        }
    
    def has_endpoint_permission(self, endpoint_url_pattern):
        """Check if this token user has permission to access an endpoint."""
        return self.allowed_endpoints.filter(
            url_pattern=endpoint_url_pattern,
            is_active=True
        ).exists()
    
    def get_allowed_endpoints_list(self):
        """Get list of allowed endpoint URL patterns."""
        return list(self.allowed_endpoints.filter(is_active=True).values_list('url_pattern', flat=True))


class TokenPermission(models.Model):
    """Junction table linking TokenUser with allowed APIEndpoints."""
    
    # Relationships
    token_user = models.ForeignKey(TokenUser, on_delete=models.CASCADE, related_name='endpoint_permissions')
    endpoint = models.ForeignKey(APIEndpoint, on_delete=models.CASCADE, related_name='user_permissions')
    
    # Audit trail
    granted_at = models.DateTimeField(auto_now_add=True, help_text="When permission was granted")
    granted_by = models.CharField(max_length=100, blank=True, help_text="Admin who granted this permission")
    notes = models.TextField(blank=True, help_text="Why this permission was granted")
    
    class Meta:
        db_table = 'token_permissions'
        verbose_name = 'Token Permission'
        verbose_name_plural = 'Token Permissions'
        unique_together = [['token_user', 'endpoint']]
        ordering = ['-granted_at']
        indexes = [
            models.Index(fields=['token_user', 'endpoint']),
        ]
    
    def __str__(self):
        return f"{self.token_user.name} → {self.endpoint.name}"


class APIToken(models.Model):
    """Simple API tokens for authentication."""
    
    TOKEN_TYPES = [
        ('access', 'Access Token'),
        ('refresh', 'Refresh Token'),
    ]
    
    # Token identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    token_user = models.ForeignKey(TokenUser, on_delete=models.CASCADE, related_name='tokens')
    token_type = models.CharField(max_length=10, choices=TOKEN_TYPES)
    
    # Token data
    token = models.CharField(max_length=255, unique=True, help_text="The actual token string")
    name = models.CharField(max_length=100, blank=True, help_text="Token description")
    
    # Token lifecycle
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="When this token expires")
    last_used = models.DateTimeField(null=True, blank=True)
    
    # Token status
    is_active = models.BooleanField(default=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    # Usage tracking
    usage_count = models.PositiveIntegerField(default=0, help_text="How many times this token was used")
    last_ip = models.GenericIPAddressField(null=True, blank=True, help_text="Last IP address used")
    last_user_agent = models.TextField(blank=True, help_text="Last user agent")
    
    class Meta:
        db_table = 'api_tokens'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['token_user', 'token_type', 'is_active']),
            models.Index(fields=['expires_at', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.token_user.name} - {self.token_type} - {self.name or 'Unnamed'}"
    
    def is_expired(self):
        """Check if token is expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if token is valid (active, not expired, not revoked)."""
        return (
            self.is_active and 
            not self.is_expired() and 
            not self.revoked_at and
            self.token_user.is_active
        )
    
    def revoke(self):
        """Revoke this token."""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.save(update_fields=['is_active', 'revoked_at'])
    
    def use_token(self, ip_address=None, user_agent=None):
        """Mark token as used and update tracking info."""
        self.last_used = timezone.now()
        self.usage_count += 1
        if ip_address:
            self.last_ip = ip_address
        if user_agent:
            self.last_user_agent = user_agent
        self.save(update_fields=['last_used', 'usage_count', 'last_ip', 'last_user_agent'])
        
        # Update token user's access info
        self.token_user.update_last_access()


class AdminUser(models.Model):
    """Simple admin user for token management."""
    
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField()
    password_hash = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'admin_users'
        verbose_name = 'Admin User'
        verbose_name_plural = 'Admin Users'
    
    def __str__(self):
        return self.username
    
    def check_password(self, password):
        """Check if provided password matches."""
        from django.contrib.auth.hashers import check_password
        return check_password(password, self.password_hash)
    
    def set_password(self, password):
        """Set password for this admin user."""
        from django.contrib.auth.hashers import make_password
        self.password_hash = make_password(password)
    
    def update_last_login(self):
        """Update last login timestamp."""
        self.last_login = timezone.now()
        self.save(update_fields=['last_login'])