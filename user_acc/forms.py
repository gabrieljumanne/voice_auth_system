from django import forms 
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser
from .backends import EmailAuthBackend

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ("fullname",'username', 'email', 'password1', 'password2')
    
    def clean_email(self):
       if email := self.cleaned_data.get('email'):
           if CustomUser.objects.filter(email=email):
               raise ValidationError("This email is already in use")
           
           if email.endswith('@forbidden-domain.com'):
               raise ValidationError("This email domain is not allowed")
           
           if email.endswith('@spam.com'):
               raise ValidationError("This email provider is not allowed")
        
           return email
        
    def clean(self):
        """this perform cross fileds validation"""
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        username = cleaned_data.get('username')
        
        if email and username and username.lower() in email.lower():
            raise ValidationError("Username should not be part of the email")
        
        return cleaned_data
        

        
class CustomAuthenticationForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            {
                'class': 'form-control',
                'placeholder': 'Enter your email'
            }
        ), required=True
    )
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        }),
        required= True
    )
    
    # store the request and user in CustAuthForm 
    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user = None
        super().__init__(*args, **kwargs)
        
    
    def clean(self):
        """validate email and password and authenticate the user"""
        cleaned_data = super().clean() 
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        
        if email and password:
            backend = EmailAuthBackend()
            self.user = backend.authenticate(request=self.request,email=email, password=password)
            if not self.user:
                raise ValidationError("Invaild email or password")
            elif not self.user.is_active:
                raise ValidationError("This account is inactive ")
        
        return cleaned_data
    
    def get_user(self):
        """Retriving the authenticated user"""
        return self.user
    
        
    