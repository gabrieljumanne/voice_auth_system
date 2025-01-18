from django.conf import settings
from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.views.generic.edit import CreateView
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import PermissionDenied
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from .forms import CustomUserCreationForm, CustomAuthenticationForm


@method_decorator(sensitive_post_parameters(), name='post')
@method_decorator(never_cache, name='dispatch')
class UserRegistrationView(CreateView):
    form_class = CustomUserCreationForm
    template_name = 'account/signup.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        # Redirect logged-in users
        if request.user.is_authenticated:
            messages.info(request, "You are already registered and logged in.")
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)

        # Add a success message for the user
        messages.success(
            self.request,
            "Registration successful! Please check your email for verification."
        )
        # when the form is valid its redirect to the success_url 
        return response

    def form_invalid(self, form):
        messages.error(
            self.request,
            "Please correct the errors below."
        )
        # rerendering the form for the input  
        return super().form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'title': 'Register',
            'terms_url': reverse_lazy('terms'),
            'privacy_url': reverse_lazy('privacy'),
        })
        return context
    
class UserLogInView(LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'account/login.html'
    redirect_authenticated_user = True
    
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    @method_decorator(csrf_protect)
    @method_decorator(sensitive_variables('password'))
    def dispatch(self, request, *args, **kwargs):
        #redirect authenticated user
        if self.redirect_authenticated_user and self.request.user.is_authenticated:
            redirect_to = self.get_success_url()
            if redirect_to == self.request.path:
                raise ValueError(
                    "Redirection loop for authenticated user detected. Check that "
                    "your LOGIN_REDIRECT_URL  point to a login page."
                )
            return HttpResponseRedirect(redirect_to)
        
        if request.is_secure() and not settings.DEBUG:
            #checking the safe of redirected url 
            # works in production mode 
            # Ensure the URL is allowed
            next_url = request.POST.get('next', request.GET.get('next'))
            if next_url and not url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                raise PermissionDenied(_("Invalid redirect URL"))
            
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        """handle valid form submission"""
        #security checks before logs in 
        if not self.request.is_secure() and not settings.DEBUG:
            messages.warning(
                self.request, 
                _("login was perform over an inscure connection. "
                  "please consider using HTTPS."
                  )
            )
        # user account validation on view
        user = form.get_user()
        
        # account locking and unlocking mechanism 
        
        if hasattr(user, "is_account_locked") and user.is_account_locked():
            user.unlock_account_if_locked()
            if user.is_account_locked():
                messages.error(
                    self.request,
                    _("Your account is currently locked. Please try again later.")
                )
                return redirect('account_locked')
        
        if not user.is_active:
            messages.error(
                self.request,
                _("Your account is inactive!. Please contanct the support",)
            )
            return self.form_invalid(form)
        
        if hasattr(user, 'is_verified') and not user.is_verified:
            messages.warning(
                self.request, 
                _("please verify your email address")
            )
        
        # reset failed login on succefully attempts
        if hasattr(user, "reset_failed_login_attempts"):
            user.reset_failed_login_attempts()
            
        messages.success(
            self.request,
            _("Welcome back, {}!").format(user.get_short_name() or user.username)
        )
        
        return super().form_valid(form)
        

    def form_invalid(self, form):
        """Handle invalid of the form"""
        user = form.get_user()
        
        
        if hasattr(user, "increment_failed_login"):
            user.increment_failed_login()

            #check if account is being locked for this attempt 
            if user.is_account_locked():
                messages.error(
                    self.request,
                    _("Your account has been locked due to too many failed "
                        "login attempts. Please try again in 15 minutes."
                        )
                )
                return redirect('account_locked')
            
            # showing remaining attempts 
            remaining_attempts = 5 - user.failed_login_attempts
            if remaining_attempts > 0:
                messages.warning(
                    self.request,
                    _("Invalid login credentials. {} attempts remaining.").format(
                        remaining_attempts
                    )
                )
        
        messages.error(
            self.request,
            _("Invalid username or password.")
        )
        return super().form_invalid(form)
                
            
            
    def get_success_url(self):
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.GET.get('next', '')
        if redirect_to and url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts={self.request.get_host()},
            require_https=self.request.is_secure(),
        ):
            return redirect_to
        return '/home/'