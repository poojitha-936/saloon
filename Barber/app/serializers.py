
from rest_framework import serializers
from .models import CustomUser, MenuSelection, Service, Appointment
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import ValidationError
from datetime import time
from django.utils import timezone

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


class MenuSelectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = MenuSelection
        fields = ['id','name', 'description']


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = "__all__"


class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = "__all__"

    def validate_date(self, value):
        """Ensure the appointment date is in the future."""
        # Use timezone-aware date for future check
        if value < timezone.localdate():  # Use timezone-aware date (current date with timezone)
            raise serializers.ValidationError("The appointment date must be in the future.")
        return value

    def validate_time(self, value):
        """Ensure the appointment time is within working hours (9 AM - 6 PM)."""
        opening_time = time(9, 0)  # 9:00 AM
        closing_time = time(18, 0)  # 6:00 PM

        if not (opening_time <= value <= closing_time):
            raise serializers.ValidationError("The appointment time must be between 9:00 AM and 6:00 PM.")
        return value


















# class BookingSerializer(serializers.Serializer):
#     user = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all())
#       # Handling multiple services
#     frequency = serializers.ChoiceField(choices=Booking.frequency_choices)
#     duration = serializers.ChoiceField(choices=Booking.duration_choices)
#     date = serializers.DateField()
#     time = serializers.TimeField()
#     status = serializers.ChoiceField(choices=[('pending', 'Pending'), ('confirmed', 'Confirmed'), ('cancelled', 'Cancelled')], default='pending')

#     def create(self, validated_data):
#         user = validated_data('user')               # Retrieve user, service, frequency, duration, date, time
#         services = validated_data.get('service')          # It's a list of service IDs (many-to-many)
#         frequency = validated_data('frequency')
#         duration = validated_data('duration')
#         date = validated_data('date')
#         time = validated_data('time')
#         total_cost = self.calculate_total_cost(services, frequency, duration)                          # Calculate total cost
        
#         booking = Booking.objects.create(                         # Create the Booking instance
#             user=user,
#             frequency=frequency,
#             duration=duration,
#             date=date,
#             time=time,
#             total_cost=total_cost,
#             status='pending'  # Default status
#         )
#         booking.service.set(services)              # Add services to the booking (many-to-many relationship)

#         return booking

#     def calculate_total_cost(self, service, frequency, duration):
#         discount = Decimal('0.10') if duration >= 3 else Decimal('0.00')  
#         if frequency == 'weekly':
#             total_sessions = duration * 4  
#         elif frequency == 'bi-weekly':
#             total_sessions = duration * 2  
#         elif frequency == 'monthly':
#             total_sessions = duration 
        
#         total_cost = Decimal(service.price) * Decimal(total_sessions)  
#         total_cost *= (Decimal('1.00') - discount)  
#         return total_cost
    








