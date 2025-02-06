from django.conf import settings
from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView 
from django.contrib.auth import logout
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import PermissionDenied
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from .forms import CustomUserCreationForm, CustomAuthenticationForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import UserActivity



@method_decorator(sensitive_post_parameters(), name='post')
class UserRegistrationView(CreateView):
    form_class = CustomUserCreationForm
    template_name = 'account/signup.html'
    success_url = reverse_lazy('user_acc:login')
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # Redirect logged-in users
        if request.user.is_authenticated:
            messages.info(request, "You are already registered and logged in.")
            return redirect(reverse_lazy('user_acc:home'))
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
    
    #security decorators 
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    @method_decorator(csrf_protect)
    @method_decorator(sensitive_variables('password'))
    def dispatch(self, request, *args, **kwargs):
        #check if the user is already login and redirects if .
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
        
        # login user after validation
        auth_response = super().form_valid(form)
        
        #security checks after logs in 
        if not self.request.is_secure() and not settings.DEBUG:
            messages.warning(
                self.request, 
                _("login was perform over an inscure connection. "
                  "please consider using HTTPS."
                  )
            )
       
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
        
        # track the user activity after succefully login 
        try:
            UserActivity.objects.create(
            user = user,
            action = 'Logged In',
            icon = "sign-in-alt"
        )
        except IntegrityError:
            #log the error but dont stop the login process
             messages.warning(
            self.request,
            _("Unable to track login activity, but login was successful.")
        )
        
            
        messages.success(
            self.request,
            _("Welcome back, {}!").format(user.get_short_name() or user.username)
        )
        
        return auth_response
        

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
        return reverse_lazy('user_acc:home')
    

class UserLogOutView(LogoutView):
    #template_name = 'account/home.html'
    next_page = reverse_lazy("user_acc:home")
    
    @method_decorator(never_cache)
    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        
        if request.method != 'POST': 
            messages.warning(
                self.request, 
                _("Please can use the logout button to logout")
            )
            return redirect(reverse_lazy("user_acc:home"))
        
        return super().dispatch(request, *args, **kwargs)
    
    def post(self, request, *args, **kwargs):
        """processing the logout(session cleaning) and redirect the user mechanism"""
        
        # get the username 
        username = request.user.get_short_name() or request.user.username
        
        #cleaning the session sensitive data 
        for key in list(request.session.keys()):
            if key.startswith('sensitive_'):
                del request.session[key]
        
        # logout the user
        response = super().post(request, *args, **kwargs)

        messages.success(
            self.request, 
            _(f"Goodbye, {username}! , You are successfully logged out")
        )
        
        # clear all session data 
        request.session.flush()
        
        return response 
    
    def get_next_page(self):
        """Returns the url of the nextpage to redirect after the logout
        """
        next_page = self.request.POST.get('next') or self.request.GET.get('next')
        
        # validity check for the next page 
        if next_page and url_has_allowed_host_and_scheme(
            allowed_hosts={self.request.get_host()},
            require_https= self.request.is_secure()
        ):
            return next_page
        
        return super().get_next_page()
    

class Password_reset_view():
    pass



class HomepageView(TemplateView):
    """
    Homepage view that requires user authentication
    Renders the main dashboard/home page for logged-in users
    """
    template_name = 'account/home.html'
    
    def get_context_data(self, **kwargs):
        """
        Adds additional context data to the template
        """
        context = super().get_context_data(**kwargs)
        context['title'] = 'Dashboard'
        
        # featch activities if the user is only authenticated 
        if self.request.user.is_authenticated:
            context['recent_activities'] = self.get_recent_activities()
        
        return context

    def get_recent_activities(self):
        """featch user recently activities"""
        return  UserActivity.objects.filter(user=self.request.user).order_by('-timestamp')

    def post(self, request, *args, **kwargs):
        """
        Optional: Handle any POST requests on the homepage
        Useful for quick actions or form submissions
        """
        # Implement any POST handling logic here
        return self.get(request, *args, **kwargs)
    
    
def logpage(request):
    return HttpResponse("trial page ")