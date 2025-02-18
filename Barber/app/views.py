from django.views import generic
from rest_framework.views import APIView
from .serializers import RegisterSerializer, LoginSerializer, LogoutSerializer, ChangePasswordSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from rest_framework  import status
from rest_framework .permissions import IsAuthenticated
from rest_framework.response import Response
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from rest_framework import generics
# from django.contrib.auth import get_user_model

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


class ResetPasswordView(generics.GenericAPIView):
    serializer_class=ResetPasswordSerializer

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"Password updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







# class ResetPasswordView(APIView):
#     def post(self, request, token):
#         print(token)
#         try:
#             reset_entry = ResetPasswordView.objects.get(token=token)
#             # Check if the token is expired (e.g., 1 hour expiration)
#             if reset_entry.created_at + timedelta(hours=1) < timezone.now():
#                 return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)
            
#             # Token is valid and not expired
#             return Response({"message": "password reset successfull."}, status=status.HTTP_200_OK)

#         except:
#             return Response({"reset": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)




# class ResetPasswordView(APIView):

#     def get(self, request, token):
#         try:
#             reset_entry = ResetPasswordView.objects.get(token=token)
#             if reset_entry.is_expired:
#                 return Response({"error": "The reset link has expired."}, status=status.HTTP_400_BAD_REQUEST)

#             user = reset_entry.user
#             user.set_password("newpassword")
#             user.save()

#             # Optionally, delete the reset entry to prevent reuse
#             reset_entry.delete()

#             return Response({"message": "Password has been successfully reset."}, status=status.HTTP_200_OK)
        
#         except:
#             return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        


# class ResetPasswordView(APIView):   
#     def get(self, request, token):
#         try:
#             reset_entry = ResetPasswordView.objects.get(token=token)
#             if reset_entry.is_expired:
#                 raise Http404("The reset link has expired.")
#             return Response({"message": "Token is valid. Please provide a new password."}, status=status.HTTP_200_OK)
        
#         except ResetPasswordView.DoesNotExist:
#             raise Http404("Invalid token.")
    
#     def post(self, request, token):
#         new_password = request.data.get('new_password')

        # try:
        #     reset_entry = ResetPasswordView.objects.get(token=token)
        #     if reset_entry.is_expired:
        #         return Response({"error": "The reset link has expired."}, status=status.HTTP_400_BAD_REQUEST)

        #     user = reset_entry.user
        #     user.set_password("newpassword")
        #     user.save()

        #     # Optionally, delete the reset entry to prevent reuse
        #     reset_entry.delete()

        #     return Response({"message": "Password has been successfully reset."}, status=status.HTTP_200_OK)
        
        # except ResetPasswordView.DoesNotExist:
        #     return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        




    


# Create your views here.








