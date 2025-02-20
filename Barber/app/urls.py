from django.urls import path
from .views import RegisterView, LoginView, LogoutView ,ChangePasswordView, ForgotPasswordView, ResetPasswordView, GoogleLoginView, GoogleCallbackView, GuestLoginView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset-password/<str:token>/', ResetPasswordView.as_view(), name='reset_password'),
    path("auth/google/login/", GoogleLoginView.as_view(), name="google-login"),
    path("auth/google/callback/", GoogleCallbackView.as_view(), name="google-callback"),
    path('auth/guest-login/', GuestLoginView.as_view(), name='guest-login'),
]