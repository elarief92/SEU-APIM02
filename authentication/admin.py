from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import TokenUser, APIToken, AdminUser, APIEndpoint, TokenPermission


@admin.register(APIEndpoint)
class APIEndpointAdmin(admin.ModelAdmin):
    """Admin interface for API Endpoint management."""
    
    list_display = [
        'name', 'url_pattern', 'category', 'is_active',
        'authorized_users_count', 'created_at'
    ]
    
    list_filter = ['category', 'is_active', 'created_at']
    
    search_fields = ['name', 'url_pattern', 'description']
    
    # Enable autocomplete for this model
    autocomplete_fields = []
    
    readonly_fields = ['created_at', 'updated_at', 'authorized_users_list']
    
    fieldsets = (
        ('Endpoint Information', {
            'fields': ('name', 'url_pattern', 'description', 'category')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Authorized Users', {
            'fields': ('authorized_users_list',),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def authorized_users_count(self, obj):
        """Display count of users with access to this endpoint."""
        count = obj.user_permissions.count()
        if count > 0:
            return format_html(
                '<span style="color: green; font-weight: bold;">{} users</span>',
                count
            )
        return format_html('<span style="color: gray;">0 users</span>')
    authorized_users_count.short_description = 'Authorized Users'
    
    def authorized_users_list(self, obj):
        """Display list of users authorized to use this endpoint."""
        if not obj.pk:
            return "Save the endpoint first"
        
        permissions = obj.user_permissions.select_related('token_user').all()
        
        if not permissions.exists():
            return format_html(
                '<p style="color: #6c757d; font-style: italic;">No users authorized for this endpoint yet.</p>'
            )
        
        html = '<ul style="margin: 0; padding-left: 20px;">'
        for perm in permissions:
            html += f'''
            <li>
                <strong>{perm.token_user.name}</strong> ({perm.token_user.company or 'No company'})
                <br><small style="color: #6c757d;">
                    Granted: {perm.granted_at.strftime('%Y-%m-%d %H:%M')}
                    {f" by {perm.granted_by}" if perm.granted_by else ""}
                </small>
            </li>
            '''
        html += '</ul>'
        
        return format_html(html)
    authorized_users_list.short_description = 'Authorized Users List'


class TokenPermissionInline(admin.TabularInline):
    """Inline admin for managing token permissions."""
    model = TokenPermission
    extra = 1
    
    fields = ['endpoint', 'granted_by', 'notes', 'granted_at']
    readonly_fields = ['granted_at']
    
    autocomplete_fields = ['endpoint']
    
    def get_queryset(self, request):
        """Optimize queryset with related objects."""
        return super().get_queryset(request).select_related('endpoint')


@admin.register(TokenPermission)
class TokenPermissionAdmin(admin.ModelAdmin):
    """Admin interface for Token Permission management."""
    
    list_display = [
        'token_user', 'endpoint', 'endpoint_category', 
        'granted_by', 'granted_at'
    ]
    
    list_filter = [
        'endpoint__category', 'granted_at', 'granted_by'
    ]
    
    search_fields = [
        'token_user__name', 'token_user__email', 'endpoint__name',
        'granted_by', 'notes'
    ]
    
    readonly_fields = ['granted_at']
    
    autocomplete_fields = ['token_user', 'endpoint']
    
    fieldsets = (
        ('Permission Details', {
            'fields': ('token_user', 'endpoint')
        }),
        ('Audit Information', {
            'fields': ('granted_by', 'notes', 'granted_at')
        }),
    )
    
    def endpoint_category(self, obj):
        """Display endpoint category."""
        return obj.endpoint.get_category_display()
    endpoint_category.short_description = 'Category'
    
    def save_model(self, request, obj, form, change):
        """Auto-fill granted_by field with current user."""
        if not change:  # Only for new permissions
            obj.granted_by = request.user.username
        super().save_model(request, obj, form, change)


@admin.register(TokenUser)
class TokenUserAdmin(admin.ModelAdmin):
    """Admin interface for TokenUser management."""
    
    list_display = [
        'name', 'company', 'email', 'is_active', 
        'permissions_count', 'total_requests', 'last_access', 
        'active_tokens_count', 'created_at', 'token_actions'
    ]
    
    list_filter = [
        'is_active', 'created_at', 'last_access', 'company'
    ]
    
    search_fields = [
        'name', 'email', 'company', 'created_by', 'notes'
    ]
    
    # Enable autocomplete for TokenUser
    autocomplete_fields = []
    
    readonly_fields = [
        'id', 'total_requests', 'last_access', 'created_at', 
        'updated_at', 'active_tokens_display', 'user_tokens_detail',
        'permissions_summary'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'email', 'company')
        }),
        ('Token Settings', {
            'fields': (
                'is_active', 
                'access_token_lifetime_hours', 
                'refresh_token_lifetime_days'
            )
        }),
        ('Admin Information', {
            'fields': ('created_by', 'notes')
        }),
        ('Endpoint Permissions', {
            'fields': ('permissions_summary',),
            'description': 'API endpoints this token user can access'
        }),
        ('User Tokens', {
            'fields': ('user_tokens_detail',),
            'description': 'All access and refresh tokens for this user'
        }),
        ('Usage Statistics', {
            'fields': (
                'total_requests', 'last_access', 'active_tokens_display'
            ),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['generate_new_tokens', 'revoke_all_tokens', 'activate_users', 'deactivate_users']
    
    inlines = [TokenPermissionInline]
    
    def get_queryset(self, request):
        """Optimize queryset with related objects."""
        return super().get_queryset(request).prefetch_related('tokens')
    
    def save_model(self, request, obj, form, change):
        """Automatically generate tokens when creating a new TokenUser."""
        is_new = obj.pk is None
        
        # Save the object first
        super().save_model(request, obj, form, change)
        
        # If this is a new TokenUser, generate tokens automatically
        if is_new:
            tokens = obj.create_tokens()
            
            # Show success message with the generated tokens
            message_text = f"""🎉 New TokenUser Created: {obj.name}

    Access Token: {tokens['access_token']}

    Refresh Token: {tokens['refresh_token']}

    Expires: {tokens['access_expires_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}

    ⚠️ Save these tokens now - they won't be shown again!"""
            
            from django.contrib import messages
            messages.success(request, message_text)
    
    def permissions_count(self, obj):
        """Display count of allowed endpoints."""
        count = obj.allowed_endpoints.filter(is_active=True).count()
        if count > 0:
            return format_html(
                '<span style="color: #1B8354; font-weight: bold;">{} endpoints</span>',
                count
            )
        return format_html('<span style="color: orange;">0 endpoints</span>')
    permissions_count.short_description = 'Permissions'
    
    def permissions_summary(self, obj):
        """Display summary of allowed endpoints."""
        if not obj.pk:
            return "Save the token user first"
        
        endpoints = obj.allowed_endpoints.filter(is_active=True).order_by('category', 'name')
        
        if not endpoints.exists():
            return format_html(
                '<div style="padding: 15px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px;">'
                '<p style="margin: 0; color: #856404; text-align: center;">'
                '⚠️ No endpoint permissions assigned!<br>'
                '<small>This token user cannot access any API endpoints. Assign permissions below.</small>'
                '</p></div>'
            )
        
        # Group by category
        from itertools import groupby
        html = '<div style="max-width: 100%;">'
        
        for category, group in groupby(endpoints, key=lambda x: x.category):
            endpoints_list = list(group)
            category_display = dict(APIEndpoint.CATEGORY_CHOICES).get(category, category)
            
            html += f'''
            <div style="margin-bottom: 20px; background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #1B8354;">
                <h4 style="margin: 0 0 10px 0; color: #1B8354;">
                    {category_display} ({len(endpoints_list)} endpoints)
                </h4>
                <ul style="margin: 0; padding-left: 20px; columns: 2; column-gap: 20px;">
            '''
            
            for endpoint in endpoints_list:
                html += f'''
                <li style="margin-bottom: 5px; break-inside: avoid;">
                    <strong>{endpoint.name}</strong>
                    <br><small style="color: #6c757d; font-family: monospace;">{endpoint.url_pattern}</small>
                </li>
                '''
            
            html += '</ul></div>'
        
        html += '</div>'
        
        return format_html(html)
    permissions_summary.short_description = 'Allowed Endpoints'
    
    def active_tokens_count(self, obj):
        """Display count of active tokens."""
        count = obj.tokens.filter(is_active=True, token_type='access').count()
        if count > 0:
            return format_html(
                '<span style="color: green; font-weight: bold;">{}</span>', 
                count
            )
        return format_html('<span style="color: red;">0</span>')
    active_tokens_count.short_description = 'Active Tokens'
    
    def active_tokens_display(self, obj):
        """Display active tokens information."""
        if not obj.pk:
            return "Save the token user first to see tokens"
        
        access_tokens = obj.tokens.filter(is_active=True, token_type='access')
        refresh_tokens = obj.tokens.filter(is_active=True, token_type='refresh')
        
        html = f"<strong>Access Tokens:</strong> {access_tokens.count()}<br>"
        html += f"<strong>Refresh Tokens:</strong> {refresh_tokens.count()}<br><br>"
        
        if access_tokens.exists():
            html += "<strong>Recent Access Tokens:</strong><br>"
            for token in access_tokens.order_by('-created_at')[:3]:
                expires_in = (token.expires_at - timezone.now()).total_seconds()
                if expires_in > 0:
                    hours = int(expires_in // 3600)
                    status = f"expires in {hours}h"
                else:
                    status = "EXPIRED"
                html += f"• {token.token[:20]}... ({status})<br>"
        
        return format_html(html)
    active_tokens_display.short_description = 'Active Tokens Details'
    
    def user_tokens_detail(self, obj):
        """Display comprehensive token information for this user."""
        if not obj.pk:
            return "Save the token user first to see tokens"
        
        # Get all tokens ordered by creation date
        all_tokens = obj.tokens.all().order_by('-created_at')
        
        if not all_tokens.exists():
            return format_html(
                '<div style="padding: 15px; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px;">'
                '<p style="margin: 0; color: #6c757d; text-align: center;">'
                '🔑 No tokens found for this user.<br>'
                '<small>Use the "Generate Tokens" button above to create access and refresh tokens.</small>'
                '</p></div>'
            )
        
        # Debug: Let's see what we have
        print(f"DEBUG: Found {all_tokens.count()} tokens for {obj.name}")
        
        # Separate tokens by type
        access_tokens = all_tokens.filter(token_type='access')
        refresh_tokens = all_tokens.filter(token_type='refresh')
        
        html = '<div style="max-width: 100%; overflow-x: auto;">'
        
        # Access Tokens Section
        html += '''
        <div style="margin-bottom: 25px;">
            <h3 style="margin: 0 0 10px 0; color: #198754; border-bottom: 2px solid #198754; padding-bottom: 5px;">
                🔑 Access Tokens
            </h3>
        '''
        
        if access_tokens.exists():
            html += '''
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 13px;">
                <thead>
                    <tr style="background: #e8f5e8;">
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 35%;">Access Token (Select to Copy)</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 10%;">Status</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 12%;">Created</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 15%;">Expires</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 8%;">Usage</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 12%;">Last Used</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 8%;">Last IP</th>
                    </tr>
                </thead>
                <tbody>
            '''
            
            for token in access_tokens:
                # Determine status and colors
                if not token.is_active:
                    status = "REVOKED"
                    status_color = "#dc3545"
                    row_bg = "#f8d7da"
                elif token.is_expired():
                    status = "EXPIRED"
                    status_color = "#fd7e14"
                    row_bg = "#fff3cd"
                else:
                    status = "ACTIVE"
                    status_color = "#198754"
                    row_bg = "#d1e7dd"
                
                # Time calculations
                expires_in = (token.expires_at - timezone.now()).total_seconds()
                if expires_in > 0:
                    hours_left = int(expires_in // 3600)
                    expires_display = f"{token.expires_at.strftime('%m/%d %H:%M')} ({hours_left}h left)"
                else:
                    expires_display = f"{token.expires_at.strftime('%m/%d %H:%M')} (expired)"
                
                html += f'''
                <tr style="background: {row_bg};">
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 11px; word-break: break-all;">
                        <div style="background: #f8f9fa; padding: 4px; border-radius: 3px; border: 1px solid #dee2e6; user-select: all;">
                            {token.token}
                        </div>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong style="color: {status_color};">{status}</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {token.created_at.strftime('%m/%d %H:%M')}
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {expires_display}
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                        <span style="background: #f8f9fa; padding: 2px 6px; border-radius: 3px;">
                            {token.usage_count}
                        </span>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {token.last_used.strftime('%m/%d %H:%M') if token.last_used else 'Never'}
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 11px;">
                        {token.last_ip or 'N/A'}
                    </td>
                </tr>
                '''
            
            html += '</tbody></table>'
        else:
            html += '<p style="color: #6c757d; font-style: italic;">No access tokens found.</p>'
        
        html += '</div>'
        
        # Refresh Tokens Section
        html += '''
        <div style="margin-bottom: 15px;">
            <h3 style="margin: 0 0 10px 0; color: #0d6efd; border-bottom: 2px solid #0d6efd; padding-bottom: 5px;">
                🔄 Refresh Tokens
            </h3>
        '''
        
        if refresh_tokens.exists():
            html += '''
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 13px;">
                <thead>
                    <tr style="background: #e7f3ff;">
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 40%;">Refresh Token (Select to Copy)</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 12%;">Status</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 15%;">Created</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 18%;">Expires</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 10%;">Usage</th>
                        <th style="padding: 8px; border: 1px solid #ddd; text-align: left; width: 15%;">Last Used</th>
                    </tr>
                </thead>
                <tbody>
            '''
            
            for token in refresh_tokens:
                # Determine status and colors
                if not token.is_active:
                    status = "REVOKED"
                    status_color = "#dc3545"
                    row_bg = "#f8d7da"
                elif token.is_expired():
                    status = "EXPIRED"
                    status_color = "#fd7e14"
                    row_bg = "#fff3cd"
                else:
                    status = "ACTIVE"
                    status_color = "#0d6efd"
                    row_bg = "#cce7ff"
                
                # Time calculations
                expires_in = (token.expires_at - timezone.now()).total_seconds()
                if expires_in > 0:
                    days_left = int(expires_in // 86400)
                    expires_display = f"{token.expires_at.strftime('%m/%d %H:%M')} ({days_left}d left)"
                else:
                    expires_display = f"{token.expires_at.strftime('%m/%d %H:%M')} (expired)"
                
                html += f'''
                <tr style="background: {row_bg};">
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 11px; word-break: break-all;">
                        <div style="background: #f8f9fa; padding: 4px; border-radius: 3px; border: 1px solid #dee2e6; user-select: all;">
                            {token.token}
                        </div>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        <strong style="color: {status_color};">{status}</strong>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {token.created_at.strftime('%m/%d %H:%M')}
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {expires_display}
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                        <span style="background: #f8f9fa; padding: 2px 6px; border-radius: 3px;">
                            {token.usage_count}
                        </span>
                    </td>
                    <td style="padding: 8px; border: 1px solid #ddd;">
                        {token.last_used.strftime('%m/%d %H:%M') if token.last_used else 'Never'}
                    </td>
                </tr>
                '''
            
            html += '</tbody></table>'
        else:
            html += '<p style="color: #6c757d; font-style: italic;">No refresh tokens found.</p>'
        
        html += '</div>'
        
        # Summary Statistics
        active_access = access_tokens.filter(is_active=True, expires_at__gt=timezone.now()).count()
        active_refresh = refresh_tokens.filter(is_active=True, expires_at__gt=timezone.now()).count()
        total_usage = sum(token.usage_count for token in all_tokens)
        
        html += f'''
        <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; border: 1px solid #dee2e6;">
            <strong>📊 Token Summary:</strong> 
            {active_access} active access token(s), 
            {active_refresh} active refresh token(s), 
            {total_usage} total API calls made
        </div>
        '''
        
        html += '</div>'
        
        return format_html(html)
    user_tokens_detail.short_description = 'User Tokens'
    
    def token_actions(self, obj):
        """Display action buttons for token management."""
        if not obj.pk:
            return "Save first"
        
        active_tokens = obj.tokens.filter(is_active=True).count()
        
        html = f"""
        <a href="/apim/admin/authentication/tokenuser/{obj.pk}/generate-tokens/" 
           style="background: #417690; color: white; padding: 5px 10px; text-decoration: none; border-radius: 3px; margin-right: 5px;">
           Generate Tokens
        </a>
        """
        
        if active_tokens > 0:
            html += f"""
            <a href="/apim/admin/authentication/tokenuser/{obj.pk}/revoke-tokens/" 
               style="background: #ba2121; color: white; padding: 5px 10px; text-decoration: none; border-radius: 3px;">
               Revoke All ({active_tokens})
            </a>
            """
        else:
            html += '<span style="color: #666; font-size: 12px;">No active tokens</span>'
        
        return format_html(html)
    token_actions.short_description = 'Actions'
    
    def generate_new_tokens(self, request, queryset):
        """Admin action to generate new tokens for selected users."""
        results = []
        for token_user in queryset:
            if token_user.is_active:
                tokens = token_user.create_tokens()
                results.append(f"Generated tokens for {token_user.name}")
            else:
                results.append(f"Skipped inactive user: {token_user.name}")
        
        self.message_user(request, f"Token generation complete. {'; '.join(results)}")
    generate_new_tokens.short_description = "Generate new tokens for selected users"
    
    def revoke_all_tokens(self, request, queryset):
        """Admin action to revoke all tokens for selected users."""
        total_revoked = 0
        for token_user in queryset:
            revoked = 0
            for token in token_user.tokens.filter(is_active=True):
                token.revoke()
                revoked += 1
            total_revoked += revoked
        
        self.message_user(request, f"Revoked {total_revoked} tokens for {queryset.count()} users")
    revoke_all_tokens.short_description = "Revoke all tokens for selected users"
    
    def activate_users(self, request, queryset):
        """Admin action to activate selected users."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"Activated {updated} token users")
    activate_users.short_description = "Activate selected users"
    
    def deactivate_users(self, request, queryset):
        """Admin action to deactivate selected users."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"Deactivated {updated} token users")
    deactivate_users.short_description = "Deactivate selected users"
    
    def get_urls(self):
        """Add custom URLs for token management."""
        from django.urls import path
        urls = super().get_urls()
        custom_urls = [
            path('<uuid:user_id>/generate-tokens/', self.admin_site.admin_view(self.generate_tokens_view), name='tokenuser_generate_tokens'),
            path('<uuid:user_id>/revoke-tokens/', self.admin_site.admin_view(self.revoke_tokens_view), name='tokenuser_revoke_tokens'),
        ]
        return custom_urls + urls
    
    def generate_tokens_view(self, request, user_id):
        """Admin view to generate tokens for a specific user."""
        from django.shortcuts import get_object_or_404, redirect
        from django.contrib import messages
        
        token_user = get_object_or_404(TokenUser, id=user_id)
        
        if request.method == 'POST':
            # Generate new tokens
            tokens = token_user.create_tokens()
            
            # Create simple success message
            message_text = f"""🎉 New Tokens Generated for {token_user.name}

Access Token: {tokens['access_token']}

Refresh Token: {tokens['refresh_token']}

Expires: {tokens['access_expires_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}

⚠️ Save these tokens now - they won't be shown again!"""
            
            messages.success(request, message_text)
            return redirect(f'/apim/admin/authentication/tokenuser/{user_id}/change/')
        
        # Show confirmation page
        from django.template.response import TemplateResponse
        context = {
            'title': f'Generate Tokens for {token_user.name}',
            'token_user': token_user,
            'opts': self.model._meta,
            'has_view_permission': self.has_view_permission(request, token_user),
        }
        return TemplateResponse(request, 'admin/authentication/generate_tokens_confirm.html', context)
    
    def revoke_tokens_view(self, request, user_id):
        """Admin view to revoke all tokens for a specific user."""
        from django.shortcuts import get_object_or_404, redirect
        from django.contrib import messages
        
        token_user = get_object_or_404(TokenUser, id=user_id)
        
        if request.method == 'POST':
            # Revoke all active tokens
            revoked_count = 0
            for token in token_user.tokens.filter(is_active=True):
                token.revoke()
                revoked_count += 1
            
            if revoked_count > 0:
                messages.success(request, f'Successfully revoked {revoked_count} tokens for {token_user.name}')
            else:
                messages.info(request, f'No active tokens found for {token_user.name}')
            
            return redirect(f'/apim/admin/authentication/tokenuser/{user_id}/change/')
        
        # Show confirmation page
        from django.template.response import TemplateResponse
        active_tokens = token_user.tokens.filter(is_active=True)
        context = {
            'title': f'Revoke Tokens for {token_user.name}',
            'token_user': token_user,
            'active_tokens': active_tokens,
            'active_count': active_tokens.count(),
            'opts': self.model._meta,
            'has_view_permission': self.has_view_permission(request, token_user),
        }
        return TemplateResponse(request, 'admin/authentication/revoke_tokens_confirm.html', context)
    
    class Media:
        pass  # Removed JavaScript dependency


@admin.register(APIToken)
class APITokenAdmin(admin.ModelAdmin):
    """Admin interface for APIToken management."""
    
    list_display = [
        'token_preview', 'token_user', 'token_type', 'name',
        'is_active', 'usage_count', 'expires_at', 'last_used'
    ]
    
    list_filter = [
        'token_type', 'is_active', 'created_at', 'expires_at',
        'token_user__company'
    ]
    
    search_fields = [
        'token_user__name', 'token_user__email', 'name', 'token'
    ]
    
    readonly_fields = [
        'id', 'token', 'created_at', 'usage_count', 'last_used',
        'last_ip', 'last_user_agent'
    ]
    
    fieldsets = (
        ('Token Information', {
            'fields': ('token_user', 'token_type', 'name', 'token')
        }),
        ('Token Status', {
            'fields': ('is_active', 'expires_at', 'revoked_at')
        }),
        ('Usage Statistics', {
            'fields': (
                'usage_count', 'last_used', 'last_ip', 'last_user_agent'
            ),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': ('id', 'created_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['revoke_tokens', 'activate_tokens']
    
    def token_preview(self, obj):
        """Display token preview."""
        if obj.is_active:
            color = "green" if not obj.is_expired() else "orange"
        else:
            color = "red"
        
        return format_html(
            '<span style="color: {}; font-family: monospace;">{}</span>',
            color,
            f"{obj.token[:20]}..."
        )
    token_preview.short_description = 'Token'
    
    def revoke_tokens(self, request, queryset):
        """Admin action to revoke selected tokens."""
        revoked = 0
        for token in queryset:
            if token.is_active:
                token.revoke()
                revoked += 1
        
        self.message_user(request, f"Revoked {revoked} tokens")
    revoke_tokens.short_description = "Revoke selected tokens"
    
    def activate_tokens(self, request, queryset):
        """Admin action to activate selected tokens (if not expired)."""
        activated = 0
        for token in queryset:
            if not token.is_expired() and not token.revoked_at:
                token.is_active = True
                token.save()
                activated += 1
        
        self.message_user(request, f"Activated {activated} tokens")
    activate_tokens.short_description = "Activate selected tokens (if not expired)"


@admin.register(AdminUser)
class AdminUserAdmin(admin.ModelAdmin):
    """Admin interface for AdminUser management."""
    
    list_display = [
        'username', 'email', 'is_active', 'is_superuser',
        'created_at', 'last_login'
    ]
    
    list_filter = ['is_active', 'is_superuser', 'created_at']
    
    search_fields = ['username', 'email']
    
    readonly_fields = ['password_hash', 'created_at', 'last_login']
    
    fieldsets = (
        ('User Information', {
            'fields': ('username', 'email')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_superuser')
        }),
        ('System Information', {
            'fields': ('password_hash', 'created_at', 'last_login'),
            'classes': ('collapse',)
        }),
    )


# Customize admin site headers
admin.site.site_header = "SEU APIs Token Management 02"
admin.site.site_title = "SEU APIs Admin"
admin.site.index_title = "Token Management Dashboard"
