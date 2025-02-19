import requests
from rest_framework.views import APIView

from Barber.settings import GOOGLE_TOKEN_URL, GOOGLE_USER_INFO_URL
from .serializers import RegisterSerializer, LoginSerializer, LogoutSerializer, ChangePasswordSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from rest_framework  import status
from rest_framework .permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.conf import settings
from django.shortcuts import redirect
from rest_framework.permissions import AllowAny
import logging


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
    """Handles the OAuth callback from Google."""
    def get(self, request):
        # Step 1: Get the authorization code
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Authorization code not provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Step 2: Exchange code for an access token
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        logger.info("Exchanging code for access token...")

        token_response = requests.post(settings.GOOGLE_TOKEN_URL, data=data)
        
        # Check if token response is successful
        if token_response.status_code != 200:
            logger.error(f"Failed to fetch access token: {token_response.text}")
            return Response({"error": "Failed to fetch access token"}, status=status.HTTP_400_BAD_REQUEST)

        tokens = token_response.json()
        access_token = tokens.get("access_token")

        # If there's no access token, log and return error
        if not access_token:
            logger.error("Access token is missing in response")
            return Response({"error": "Access token missing"}, status=status.HTTP_400_BAD_REQUEST)

        logger.info(f"Access token received: {access_token}")

        # Step 3: Use the access token to fetch user info
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(settings.GOOGLE_USER_INFO_URL, headers=headers)

        # Check if the response for user info is successful
        if user_info_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_info_response.text}")
            return Response({"error": "Failed to fetch user info"}, status=status.HTTP_400_BAD_REQUEST)

        user_info = user_info_response.json()
        email = user_info.get("email")
        
        # Log the email and tokens to verify
        logger.info(f"User email: {email}")
        logger.info(f"User info: {user_info}")

        # Respond with the user's email and tokens
        return Response({"email": email, "tokens": tokens}, status=status.HTTP_200_OK)
    




class GoogleCallbackView(APIView):
    """Handles the OAuth callback from Google."""
    def get(self, request):
        code = request.GET.get("code")
        if not code:
            return Response({"error": "Authorization code not provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Exchange code for an access token
        data = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        # Log the request data for debugging
        # logger.info(f"Exchanging code for access token: {data}")

        token_response = requests.post(GOOGLE_TOKEN_URL, data=data)
        print(token_response)

        if token_response.status_code != 200:
            logger.error(f"Failed to fetch access token: {token_response.text}")
            return Response({"error": "Failed to fetch access token"}, status=status.HTTP_400_BAD_REQUEST)

        tokens = token_response.json()
        print(tokens)
        access_token = tokens.get("access_token")

        if not access_token:
            logger.error("Access token missing in response")
            return Response({"error": "Access token missing"}, status=status.HTTP_400_BAD_REQUEST)

        # Log the access token for debugging
        logger.info(f"Access Token: {access_token}")

        # Use access token to fetch user info
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(GOOGLE_USER_INFO_URL, headers=headers)

        if user_info_response.status_code != 200:
            logger.error(f"Failed to fetch user info: {user_info_response.text}")
            return Response({"error": "Failed to fetch user info"}, status=status.HTTP_400_BAD_REQUEST)

        user_info = user_info_response.json()
        email = user_info.get("email")
        
        # Handle user login or registration here
        # Example: Create or fetch the user based on the email
        # user = User.objects.get_or_create(email=email, defaults={'name': user_info.get("name")})

        return Response({"email": email, "tokens": tokens}, status=status.HTTP_200_OK)





# class GoogleCallbackView(APIView):
#     """Step 2: Handle Google's OAuth 2.0 callback and exchange code for tokens"""
#     def get(self, request):
#         code = request.GET.get("code")
#         if not code:
#             return Response({"error": "Authorization code not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Exchange code for an access token
#         data = {
#             "code": code,
#             "client_id": settings.GOOGLE_CLIENT_ID,
#             "client_secret": settings.GOOGLE_CLIENT_SECRET,
#             "redirect_uri": settings.GOOGLE_REDIRECT_URI,
#             "grant_type": "authorization_code",
#         }
#         token_response = requests.post(settings.GOOGLE_TOKEN_URL, data=data)
#         if not access_token:
#             logger.error("No access token returned from Google.")
#             return Response({"error": "Access token missing"}, status=status.HTTP_400_BAD_REQUEST)
#         # if token_response.status_code != 200:
#         #     logger.error("Failed to fetch access token: %s", token_response.text)
#         #     return Response({"error": "Failed to fetch access token"}, status=status.HTTP_400_BAD_REQUEST)

#         tokens = token_response.json()
#         access_token = tokens.get("access_token")

#         # Step 3: Use the access token to fetch user info
#         headers = {"Authorization": f"Bearer {access_token}"}
#         user_info_response = requests.get(settings.GOOGLE_USER_INFO_URL, headers=headers)
#         if user_info_response.status_code != 200:
#             logger.error("Failed to fetch user info: %s", user_info_response.text)
#             return Response({"error": "Failed to fetch user info"}, status=status.HTTP_400_BAD_REQUEST)

#         user_info = user_info_response.json()

#         # Handle user login or registration here
#         # Example: Create or fetch the user based on their Google email
#         email = user_info.get("email")
#         # name = user_info.get("name")

#         return Response({"email": email,  "tokens": tokens}, status=status.HTTP_200_OK)



        




    


# Create your views here.








