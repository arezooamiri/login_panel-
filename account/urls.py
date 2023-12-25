from django.urls import path
from .views import *

urlpatterns = [
    path('send_otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify_otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('register/',RegisterUserView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('forgot-password/', ForgotPassword.as_view(), name='forgot_password'),
    path('reset-password/', PasswordReset.as_view(), name='reset_password'),
    path('logout/',LogoutView.as_view(),name='logout')
]
