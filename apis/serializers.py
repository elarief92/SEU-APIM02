from rest_framework import serializers
from .models import  APIRequestHistory
from authentication.models import User




class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'is_admin', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class APIRequestHistorySerializer(serializers.ModelSerializer):
    """Serializer for APIRequestHistory model."""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = APIRequestHistory
        fields = ['id', 'user', 'endpoint', 'filename', 'file_type', 'file_size', 'processing_time', 'result', 'status', 'error_message', 'created_at']
        read_only_fields = ['id', 'created_at'] 