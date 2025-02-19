from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import ValidationError

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
        # Ensure new password and confirm new password match
        if data['new_password'] != data['confirm_new_password']:
            raise ValidationError("New password and confirm new password do not match.")
        return data

    def save(self, user):
        # Check if the current password is correct
        if not user.check_password(self.validated_data['current_password']):
            raise ValidationError("Current password is incorrect.")
        
        # Set the new password and save the user
        user.set_password(self.validated_data['new_password'])
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



# class ResetPasswordSerializer(serializers.Serializer):
#     token = serializers.CharField(write_only=True)
#     new_password = serializers.CharField(min_length=8, write_only=True)
#     confirm_new_password = serializers.CharField(min_length=8, write_only=True)

#     def validate(self, attrs):
#         new_password=attrs.get("new_password")
        # confirm_new_password=attrs.get("confirm_new_password")

        # try:
        #     user=User.objects.get(ne)
    #     # Check if new password and confirm password match
    #     if data['new_password'] != data['confirm_new_password']:
    #         raise ValidationError("New password and confirm new password do not match.")
        
    #     # You can add more validation logic here, like checking password complexity
    #     return data

    # def save(self):
    #     token = self.validated_data['token']
    #     new_password = self.validated_data['new_password']
        
    #     # You should verify the token in your database and retrieve the user, here we simulate token validation
    #     user = self.verify_token(token)
       
    #     if not user:
    #         raise ValidationError("Invalid or expired token.")
        
    #     # Set the new password
    #     user.set_password(new_password)
    #     user.save()

    #     return {"message": "Password has been successfully updated."}

    # def verify_token(self, token):
    #     # Here you would verify the token. In this example, we're simply returning a mock user.
    #     # This is where you would retrieve the user based on the token stored in the database.
    #     return User.objects.first()







# class ResetPasswordSerializer(serializers.Serializer):
#     token = serializers.CharField(max_length=32)
#     new_password = serializers.CharField(write_only=True, required=True)

#     def validate_token(self, value):
#         try:
#             reset_entry = ResetPasswordSerializer.objects.get(token=value)
#         except:
#             raise serializers.ValidationError("Invalid token.")

#         # Check if the token has expired (1 hour expiry time)
#         expiration_time = reset_entry.created_at + timedelta(hours=1)
#         if timezone.now() > expiration_time:
#             raise serializers.ValidationError("The reset link has expired.")
        
#         return value

#     def save(self):
#         token = self.validated_data['token']
#         new_password = self.validated_data['new_password']

#         # Get the PasswordReset entry
#         reset_entry = ResetPasswordSerializer.objects.get(token=token)
#         user = reset_entry.user

#         # Set the new password for the user
#         user.set_password(new_password)
#         user.save()

#         # Optionally, delete the token after password reset to prevent reuse
#         reset_entry.delete()

#         return {"message": "Password has been successfully reset."}


























