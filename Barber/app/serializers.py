from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token

User=get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=9, write_only=True)
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'password']
    def validate(self, attrs):
        # email = attrs.get('email', '')
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError(self.default_error_messages)
        return attrs
    def create(self, validated_data):
        return CustomUser.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=68, min_length=6,write_only=True)
    email = serializers.CharField(max_length=30, min_length=20)
    tokens = serializers.SerializerMethodField()

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")      
        # Authenticate user with email and password
        user = authenticate(email=email, password=password)
        if user is None:
            raise ValidationError("Invalid credentials")    
        # Now, get the tokens using the 'tokens' method
        tokens = user.tokens()  
        return {
            'refresh': tokens['refresh'],
            'access': tokens['access']
        }   


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:                          # Ensure new password and confirm new password match
            raise ValidationError("New password and confirm new password do not match.")
        return data

    def save(self, user):
        if not user.check_password(self.validated_data['current_password']):            # Check if the current password is correct
            raise ValidationError("Current password is incorrect.")        
        user.set_password(self.validated_data['new_password'])           # Set the new password and save the user
        user.save()
        return {"message": "Password updated successfully."}


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate if the user with the given email exists."""
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value
  

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_new_password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class GuestLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=255)
    is_guest = serializers.BooleanField(default=True)
    name = serializers.CharField(max_length=255, required=True)
    password = serializers.CharField(write_only=True, required=True)


class EditProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name']    
































