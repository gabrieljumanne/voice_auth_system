from django.urls import path
from .views import UserRegistrationView, UserLogInView, UserLogOutView, Password_reset_view, HomepageView, logpage

app_name = "user_acc"

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='registration'),
    path('login/', UserLogInView.as_view(), name='login'),
    path('logout/', UserLogOutView.as_view(), name='logout'),
    path('home/', HomepageView.as_view(), name='home'),
    path('trial/', logpage, name="trial"),
    
    # path('passwordreset/', Password_reset_view.as_view(), name='logout'),
    
]
