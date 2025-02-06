from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password
from .models import CustomUser


class EmailAuthBackend(BaseBackend):
    """Authenticate user using email and password  """
    
    def authenticate(self, request, email=None, password=None, **kwargs):
        try: 
            #retriving the user by email and check the provided password 
            user = CustomUser.objects.get(email=email)
            if user and check_password(password, user.password):
                return user
        except CustomUser.DoesNotExist:
            return None
        
        return None
    
    def get_user(self, user_id):
        """retrive the authenicated user by id """
        try:
            return CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None 