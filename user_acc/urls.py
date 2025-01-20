from django.urls import path
from .views import UserRegistrationView, UserLogInView, UserLogOutView

app_name = "user_acc"

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='registration'),
    path('login/', UserLogInView.as_view(), name='login'),
    path('logout/', UserLogOutView.as_view(), name='logout'),
]
