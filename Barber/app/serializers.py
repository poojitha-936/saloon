from urllib import response
from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import ValidationError
from datetime import timedelta, timezone
from rest_framework import status

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
    token = serializers.CharField(max_length=32)
    new_password = serializers.CharField(write_only=True, required=True)

    def validate_token(self, value):
        try:
            reset_entry = ResetPasswordSerializer.objects.get(token=value)
        except:
            raise serializers.ValidationError("Invalid token.")

        # Check if the token has expired (1 hour expiry time)
        expiration_time = reset_entry.created_at + timedelta(hours=1)
        if timezone.now() > expiration_time:
            raise serializers.ValidationError("The reset link has expired.")
        
        return value

    def save(self):
        token = self.validated_data['token']
        new_password = self.validated_data['new_password']

        # Get the PasswordReset entry
        reset_entry = ResetPasswordSerializer.objects.get(token=token)
        user = reset_entry.user

        # Set the new password for the user
        user.set_password(new_password)
        user.save()

        # Optionally, delete the token after password reset to prevent reuse
        reset_entry.delete()

        return {"message": "Password has been successfully reset."}




















# class ForgotPasswordView(APIView):
#     def post(self, request):
#         # Initialize the serializer with the request data
#         serializer = ForgotPasswordSerializer(data=request.data)

#         # Check if the serializer is valid
#         if serializer.is_valid():
#             email = serializer.validated_data['email']

#             # Generate a reset token
#             reset_token = get_random_string(32)
            
#             # Generate reset URL
#             reset_url = f"http://127.0.0.1:8000/reset-password/?token={reset_token}"

#             # Send the password reset email
#             send_mail(
#                 "Password Reset",
#                 f"Click here to reset your password: {reset_url}",
#                 "no-reply@example.com",
#                 [email],
#                 fail_silently=False
#             )

#             return response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)

#         # If the serializer is invalid, return error response
#         return response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class ForgotPasswordSerializer(serializers.Serializer):
#     email = serializers.EmailField()

#     def validate(self, attrs):

#         # Use the serializer for validation
#         if  User.objects.filter(email=attrs.get('email')).exists():
#         # if serializers.is_valid():
#         #     email = serializers.validated_data['email']
#         #     User = User.objects.get(email=email)
#             reset_token = get_random_string(length=32)

#             # Optionally, you can store this reset token in the database, 
#             # if you have a PasswordResetToken model.
#             reset_url = f"http://127.0.0.1:8000/reset-password/?token={reset_token}"

#             # Send reset email
#             send_mail(
#                 "Password Reset",
#                 f"Click here to reset your password: {reset_url}",
#                 "karrepoojitha123@gmail.com",  # Use a valid "from" email
#                 [email],
#                 fail_silently=False
#             )
#             return response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)
        
#         return response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)


    #     email = data.get('email')
    #     if not User.objects.filter(email=email).exists():
    #         raise serializers.ValidationError("No user found with this email address.")
    #     return data

    # def save(self):
    #     email = self.validated_data['email']
    #     user = User.objects.get(email=email)
    #     reset_token = get_random_string(length=32)

    #     # You we save this token to a password reset model in production

    #     reset_url = f"http://127.0.0.1:8000/reset-password/?token={reset_token}"

    #     # Send reset email
    #     send_mail(
    #         "Password Reset",
    #         f"Click here to reset your password: {reset_url}",
    #         "karrepoojitha123@.com",
    #         [email],
    #         fail_silently=False
    #     )
    #     return {"message": "Password reset link sent."}





