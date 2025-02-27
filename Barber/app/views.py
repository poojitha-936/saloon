from datetime import datetime, timedelta
from rest_framework.views import APIView
from .models import Booking, CustomUser, Service
from app.serializers import  RegisterSerializer, LoginSerializer, LogoutSerializer, ChangePasswordSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, MenuSelectionSerializer, ServiceSerializer,AppointmentSerializer, BookingSerializer, User
from rest_framework  import status
from rest_framework .permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.conf import settings
from rest_framework.permissions import AllowAny
import logging, requests
from django.contrib.auth import login


class RegisterView(APIView):
    serializer_class=RegisterSerializer
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    serializer_class=LoginSerializer
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    serializer_class=LogoutSerializer    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Logout successful!"},status=status.HTTP_204_NO_CONTENT)
        

class ChangePasswordView(APIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Pass the authenticated user to the serializer
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)  # Save changes for the current authenticated user
        return Response({"message":"Password change successful!"}, status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            # Generate a reset token
            reset_token = get_random_string(32)
            reset_url = f"http://127.0.0.1:8000/app/reset-password/{reset_token}"
            # Send the password reset email
            send_mail(
                "Password Reset",
                f"Click here to reset your password: {reset_url}",
                "karrepoojitha123@gmail.com",
                [email],
                fail_silently=False
            )
            return Response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    serializer_class=ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        token = kwargs.get('token')  # Retrieve the token from URL
        # Process the token as needed
        return Response({"message": "Password reset successful"}, status=200)
    def _is_token_expired(self, user):
        """
        Check if the token is expired. Token expiration logic can vary.
        Here, we assume the token has a 1-hour expiration time.
        """
        token_creation_time = user.reset_token_created_at  # Example field storing the token creation time
        expiration_time = token_creation_time + timedelta(hours=1)
        if datetime.now() > expiration_time:
            return True
        return False



logger = logging.getLogger(__name__)

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]
    """Step 1: Redirect user to Google's OAuth 2.0 authorization URL"""
    def get(self, request):
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
            "access_type": "offline",
            "prompt": "consent",
        }
        authorization_url = f"{settings.GOOGLE_AUTHORIZATION_URL}?{requests.compat.urlencode(params)}"
        return Response(authorization_url)


class GoogleCallbackView(APIView):
    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Authorization code not provided"}, status=status.HTTP_400_BAD_REQUEST)
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        token_response = requests.post(settings.GOOGLE_TOKEN_URL, data=data)
        if token_response.status_code != 200:
            logger.error("Failed to fetch access token: %s", token_response.text)
            return Response({"error": "Failed to fetch access token"}, status=status.HTTP_400_BAD_REQUEST)
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(settings.GOOGLE_USER_INFO_URL, headers=headers)
        if user_info_response.status_code != 200:
            logger.error("Failed to fetch user info: %s", user_info_response.text)
            return Response({"error": "Failed to fetch user info"}, status=status.HTTP_400_BAD_REQUEST)

        user_info = user_info_response.json()
        email = user_info.get("email")
        name = user_info.get("name")
        if not email:
            return Response({"error": "Failed to retrieve email from Google"}, status=status.HTTP_400_BAD_REQUEST)
        user, created = User.objects.get_or_create(email=email, defaults={"username": name})
        if created:
            user.set_unusable_password()  
            user.save()
        tokens = user.tokens() 

        return Response({"email": email, "name": name, "tokens": tokens}, status=status.HTTP_200_OK)


class GuestLoginView(APIView):
    def get(self, request):
        guest_user = CustomUser.objects.filter(username='guest_user').first()          # Check if a guest user already exists
        if not guest_user:                                                             # If no guest user exists, create a new one
            username = "guest_user"
            guest_email = f"{username}@gmail.com"           
            user = CustomUser.objects.create_user(
                user_type='customer',
                username=username,
                email=guest_email,
                password=None                                                           # Guest user does not need a password
            )
            user.first_name = 'Guest'                                                   # Default name for guest users
            user.is_active = True                                                       # Mark as active
            user.save() 
            user.backend = 'django.contrib.auth.backends.ModelBackend'  
            login(request, user)                                                        # Log in the guest user                    
            request.session['username'] = username                                      # Store the session
            print(request.session.session_key)                                          # Debugging line (remove for production)
            return Response(
                {"message": "Logged in successfully", "user": {"username": username}},
                status=status.HTTP_200_OK
            )  
        else:     
            username = guest_user.username
            guest_user.backend = 'django.contrib.auth.backends.ModelBackend'                # If guest user exists, log them in without creating a new one
            login(request, guest_user)
            request.session['username'] = guest_user.username                               # Store the session
            print(request.session.session_key)                                              # Debugging line (remove for production)
            return Response({"message": "Welcome back, guest!", "user": {"username": guest_user.username}},status=status.HTTP_200_OK
        )


class EditProfileView(APIView):
    permission_classes = [IsAuthenticated]                         # Ensure only authenticated users can edit their profile

    def get(self, request, *args, **kwargs):                       # GET method: Fetch the user profile
        user = request.user                                        # Access the currently authenticated user (request.user)
        return Response({                                          # Return the user's profile data directly (email, username, first_name)
            'email': user.email,
            'username': user.username}, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):                           # PUT method: Update the user profile (email, username, first_name)
        user = request.user                                            # Access the currently authenticated user (request.user)
        email = request.data.get('email', user.email)                  # Validate and update the user's data directly
        username = request.data.get('username', user.username)
        user.email = email                                             # Update the user with the new values
        user.username = username
        user.save()                                                    # Save the updated user data
        return Response({"message": "Profile updated successfully!"}, status=status.HTTP_200_OK)


class MenuSelectionView(APIView):
    """
    Allow users to select services. Here, we retrieve all services for the user to choose from.
    """
    def post(self, request):
        serializer = MenuSelectionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"MenuSelection successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)       # Return validation errors if the data is not valid
        

class ServiceView(APIView):
    """
    API view to create a new service.
    """

    def post(self, request):
        serializer = ServiceSerializer(data=request.data)                          # Initialize the serializer with the incoming data (request.data)
        if serializer.is_valid():                                                  # Check if the incoming data is valid       
            serializer.save()                                                      # Save the new service to the database
            return Response(serializer.data, status=status.HTTP_201_CREATED)       # Return the serialized data in the response with a 201 CREATED status 
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)     # If the data is not valid, return the validation errors


class AppointmentCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):                                                                            # Log the user for debugging purposes
        print(f"Request User: {request.user.id}")
        user = CustomUser.objects.filter(id=request.user.id).first()                                    # Filter the user by ID (assuming the user is authenticated)
        
        if not user:
            return Response({"detail": "User not found."}, status=status.HTTP_400_BAD_REQUEST)
        service_ids = request.data.get("service", [])                                                   # Filter services by IDs from the request
        services = Service.objects.filter(id__in=service_ids)
        
        if len(services) != len(service_ids):
            return Response({"detail": "One or more services do not exist."}, status=status.HTTP_400_BAD_REQUEST)
        appointment_data = {                                                                           # Create an Appointment instance using the validated data
            'user': user.id,
            'service': [service.id for service in services],                                           # Get list of service IDs
            'date': request.data.get("date"),
            'time': request.data.get("time"),
            'status': request.data.get("status", "pending"),                                           # Default to "pending" if not provided
        }
        serializer = AppointmentSerializer(data=appointment_data)                                      # Initialize the serializer with the validated data
        
        if serializer.is_valid():
            serializer.save()                                                                          # Create and save the Appointment object
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)                     # If validation fails, return errors


class BookingView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = BookingSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    









    # def post(self, request):
    # service_ids, frequency, duration, date, time = request.data.get('service', []), request.data.get('frequency'), request.data.get('duration'), request.data.get('date'), request.data.get('time')
    # if not all([service_ids, frequency, duration, date, time]):
    #     return Response({"detail": "All fields (service, frequency, duration, date, time) are required."}, status=status.HTTP_400_BAD_REQUEST)
    
    # if Booking.objects.filter(user=request.user, frequency=frequency, service__id__in=service_ids).exists():
    #     return Response({"detail": "You already have a booking with this service and frequency."}, status=status.HTTP_400_BAD_REQUEST)
    
    # if not Service.objects.filter(id__in=service_ids).count() == len(service_ids):
    #     return Response({"detail": "One or more services do not exist."}, status=status.HTTP_400_BAD_REQUEST)

    # booking_data = {'user': request.user.id, 'service': service_ids, 'frequency': frequency, 'duration': duration, 'date': date, 'time': time}
    # serializer = BookingSerializer(data=booking_data)
    # if serializer.is_valid():
    #     booking = serializer.save(user=request.user)
    #     return Response(serializer.data, status=status.HTTP_201_CREATED)
    # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # Proceed with creating the booking...




# Create your views here.





