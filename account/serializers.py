from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User
SECURITY_QUESTION_CHOICES = (
    ('question1', 'What is your favorite color?'),
    ('question2', 'What is the name of your first pet?'),
    ('question3', "What is your mother's maiden name?"),
    ('question4','what is  the name of your first friend?'),
    ('question 5','what is your favorite food?')
    )

class OTPRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model =OTPRequest
        fields = ['email']
class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp= serializers.CharField(max_length=6)
    
class UserRegistrationSerializer(serializers.Serializer):
   
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    select_security_question = serializers.ChoiceField(choices=SECURITY_QUESTION_CHOICES)
    security_answer = serializers.CharField(max_length=100)
    otp = serializers.CharField(required=True) # Add this line to include the otp field

    def validate(self, data):
        # Validate the OTP code here
        email = data.get('email')
        otp = data.get('otp')
        try:
            otp_request = OTPRequest.objects.get(email=email,otp=otp)
            if otp_request.otp != otp:
                raise serializers.ValidationError('Invalid OTP code.')
            otp_request.delete()
        except OTPRequest.DoesNotExist:
            raise serializers.ValidationError('Email is not verified.')
          
        return data


    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email is already registered')
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters long')
        return value
    def update(self,instance,validated_data):
        instance.email=validated_data.get('email',instance.email)
        instance.password=validate_email.get('password',instance.password)
        instance.select_security_question=validated_data.get('select_security_question',instance.select_security_question)
        instance.security_answer=validated_data.get('security_answer',instance.security_answer)
        instance.save()
        return instance
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=128, write_only=True)


class ForgotPasswordSerializer(serializers.Serializer):
    email=serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    email=serializers.EmailField()
    otp=serializers.CharField(max_length=6)
    select_security_question = serializers.ChoiceField(
        choices=SECURITY_QUESTION_CHOICES
    )
    security_answer = serializers.CharField(max_length=100)
    new_password=serializers.CharField(write_only=True,min_length=6)
   



  






