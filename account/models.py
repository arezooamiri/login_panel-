from django.contrib.auth.models import AbstractBaseUser,BaseUserManager
from django.core.validators import validate_email
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

    

class UserProfile(models.Model):
    SECURITY_QUESTION_CHOICES = (
    ('question1', 'What is your favorite color?'),
    ('question2', 'What is the name of your first pet?'),
    ('question3', "What is your mother's maiden name?"),
    ('question4','what is  the name of your first friend?'),
    ('question 5','what is your favorite food?')
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email = models.EmailField(unique=True)  
    select_security_question=models.CharField(max_length=200,choices=SECURITY_QUESTION_CHOICES,default='question1')
    security_answer=models.CharField(max_length=400)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)


class OTPRequest(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.email} - {self.otp}"
    def  has_expired(self):
        expiration_time = self.created_at + timezone.timedelta(minutes=5)
    
        return  timezone.now() >= expiration_time
class Resetpassword(models.Model):
    user=models.ForeignKey(UserProfile,on_delete=models.CASCADE)
    otp=models.CharField(max_length=6)



