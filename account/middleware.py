from django.contrib.auth import logout
from django.utils import timezone
from datetime import timedelta
from rest_framework.response import Response
from rest_framework import status


class LogoutInactiveUserMiddleware:
    def __init__(self,get_response):
        self.get_response=get_response
    
    def __call__(self,request):
        response=self.get_response(request)
        

        if request.user.is_authenticated:
            last_activity=request.session.get('last_activity')
            if last_activity and timezone.now()-last_activity> timedelta(minutes=10):
                logout(request)
                response=Response({'message': 'You have been logged out due to inactivity.'}, status=status.HTTP_401_UNAUTHORIZED)

            request.session['last_activity']=timezone.now()
        return response