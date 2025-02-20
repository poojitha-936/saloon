from datetime import datetime, timedelta
from rest_framework.views import APIView
from .serializers import RegisterSerializer, LoginSerializer, LogoutSerializer, ChangePasswordSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, GuestLoginSerializer, User
from rest_framework  import status
from rest_framework .permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.conf import settings
from rest_framework.permissions import AllowAny
import logging, requests, random, string
from django.contrib.auth import get_user_model, login



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
    permission_classes = [AllowAny]  # No authentication required for guest login

    def post(self, request, *args, **kwargs):
        # Use a static email and username for the guest user
        guest_email = "guest@example.com"
        guest_username = "guest_user"
        User.save()

        # The data for the guest user (no password is needed)
        guest_user_data = {
            'email': guest_email,
            'username': guest_username,
            'is_guest': True, 
             # Mark this as a guest user
        }

        # Serialize the guest user data
        serializer = GuestLoginSerializer(data=guest_user_data)

        # Check if the serializer is valid
        if serializer.is_valid():
            return Response({
                'message': 'Guest login successful',
                'guest_user': serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'error': 'Failed to create guest user'
            }, status=status.HTTP_400_BAD_REQUEST)


# Create your views here.



class guestLogin(APIView):
    def post(self,request):
        guest_user=User.objects.filter(username='guest_user').first()
        if not guest_user:
            username="guest_user"
            user=User.objects.create_user(user_type='customer', email=f"{username}@gmail.com",name=f"{username}",username=username,password=None)
            user.is_active=True
            user.is_guest=True
            user.save()
            guest_user.backend='django.contrib.auth.backends.ModelBackend'
            login(request,guest_user)
            request.session['username']='guest_user'
            print(request.sessions.session_key)
            return Response({'message':'welcome'},status=status.HTTP_200_OK)







