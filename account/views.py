from django.core.mail import send_mail
from django.conf import settings
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import generics, status
from django.core.exceptions import ObjectDoesNotExist
import random
from .models import *
from .serializers import *
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import authenticate,login
from rest_framework.generics import CreateAPIView,UpdateAPIView
from account.models import UserProfile
from django.contrib.auth import logout

class SendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = str(random.randint(100000, 999999))
        send_mail(
            'OTP Code',
            f'Your OTP code is: {otp}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
       
        otp_request = OTPRequest.objects.create(email=email, otp=otp)
        otp_request.save()

        return Response({'message': 'OTP code sent successfully.'}, status=status.HTTP_200_OK)
class VerifyOTPView(GenericAPIView):
    serializer_class = OTPVerificationSerializer
    
    def get_queryset(self):
        return OTPRequest.objects.all()
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data.get('email')
        otp = request.data.get('otp')
        try:
            otp_request = OTPRequest.objects.get(email=email, otp=otp)

        except OTPRequest.DoesNotExist:
            raise ValidationError('Invalid email or OTP code.')
        if otp_request.has_expired():
            otp_request.delete()
            raise ValidationError('OTP code has expired.')
        otp_request.save()
        
           
        return Response({'message': 'OTP code verified successfully.'}, status=status.HTTP_200_OK)




class RegisterUserView(GenericAPIView):
    queryset = UserProfile.objects.none() 

    serializer_class = UserRegistrationSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        select_security_question = serializer.validated_data['select_security_question']
        security_answer = serializer.validated_data['security_answer']

       
        user = User.objects.create_user(username=email,email=email, password=password)
        UserProfile.objects.create(user=user,email=email, select_security_question=select_security_question, security_answer=security_answer)

        return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

      
        user = authenticate(request, username=email, password=password)

        if user is not None:
           
            login(request, user)
            return Response({'message': 'Login successful.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid email or password.'}, status=status.HTTP_401_UNAUTHORIZED)

class ForgotPassword(CreateAPIView):
    serializer_class=ForgotPasswordSerializer()

    def create(self,request):
        email=request.data.get('email')
        user=UserProfile.objects.filter(email=email).first()

        if user:
            otp = str(random.randint(100000, 999999))
            send_mail(
                'OTP Code',
                f'Your OTP code is: {otp}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
          
            user.otp=otp
            user.save()
            Resetpassword.objects.create(user=user,otp=otp)
            return Response({"message":"otp code sent successfully"},status=status.HTTP_200_OK)
        else:
            return Response({'message': 'User with this email not found.'}, status=status.HTTP_400_BAD_REQUEST)

class PasswordReset(generics.CreateAPIView):
    serializer_class=ResetPasswordSerializer
    queryset = UserProfile.objects.all()

    def create (self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        select_security_question=request.data.get('select_security_question')
        security_answer=request.data.get('security_answer')


        try:
            user_profile = UserProfile.objects.get(email=email)
         

        except UserProfile.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            otp = Resetpassword.objects.get(user=user_profile, otp=otp)
        except Resetpassword.DoesNotExist:
         
            return Response({"message": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
        
        if user_profile.select_security_question==select_security_question and user_profile.security_answer==security_answer:
           

            serializer = self.get_serializer(data=request.data)

            if serializer.is_valid():
            # Update the user's password
               new_password = serializer.validated_data['new_password']
               user_profile.user.set_password(new_password)  # Use set_password to hash the password
               user_profile.user.save()

            # Delete the OTP since it's no longer needed
               otp.delete()
               return Response({"message": "Password reset successfully."},status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"message": "Your security question or answer is not correct"},status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)