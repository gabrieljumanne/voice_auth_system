from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, Group, Permission
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from secrets import token_urlsafe
from PIL import Image
from .manager import CustomUserManager, CustomUserQueryManager


class CustomUser(AbstractBaseUser, PermissionsMixin):
    # core identity field
    email = models.EmailField(
        _("email address"),
        unique=True,
        help_text=_("Email must be unique")
    )

    username = models.CharField(
        _("user name"),
        max_length=50,
        unique=True,
        validators=[RegexValidator(
            regex=r'^[a-zA-Z0-9]+$',
            message=_("Username must be alphanumeric or must contain underscore")
        ), ]
    )

    fullname = models.CharField(
        _("user full name"),
        max_length=250,
        unique=False,
        help_text=_('Enter your full name as appeared on your official document')

    )

    # profile field
    date_of_birth = models.DateField(
        _("date of birth"),
        null=True,
        blank=True,
        help_text=_("Enter your age (optional) for age verification")

    )

    profile_picture = models.ImageField(
        _("user image"),
        blank=True,
        upload_to='profile_pictures/',
        null=True,
        help_text=_("Upload your image (optional)"),
    )

    bio = models.TextField(
        _("user bio"),
        max_length=300,
        null=True,
        blank=True,
        help_text=_("Tell us a bit about yourself (max 500 characters)")
    )

    # account management
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_("Designates whether this user account should be treated as active")
    )

    is_staff = models.BooleanField(
        _('staff'),
        default=False,
        help_text=_("Designates whether this user account should be treated as staff")
    )

    is_verified = models.BooleanField(
        _("verified"),
        default=False,
        help_text=_("Designates whether this user account should be treated as verified")
    )

    deleted_at = models.DateTimeField(
        _("deleted at"),
        null=True,
        blank=True,
        help_text=_("Timestamp for soft deletion.")
    )

    # authentication and security fields
    email_confirmation_token = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )

    password_reset_token = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )

    # advanced tracking field (security)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    date_joined = models.DateTimeField(
        _("date joined"),
        default=timezone.now
    )

    last_login = models.DateTimeField(
        _('last_login'),
        null=True,
        blank=True,
    )

    last_login_ip = models.GenericIPAddressField(
        _("last login ip"),
        null=True,
        blank=True,
    )

    failed_login_attempts = models.PositiveIntegerField(
        _("failed login attempts"),
        default=0,
        validators=[MaxValueValidator(10)]
    )

    last_failed_login = models.DateTimeField(
        _("last failed login"),
        null=True,
        blank=True
    )

    account_locked_until = models.DateTimeField(
        _("account locked until"),
        null=True,
        blank=True,
    )

    # account preference
    language_preferences = models.CharField(
        _("language preference"),
        max_length=20,
        choices=[
            ('eng', _("English")),
            ('swa', _("swahili")),
            ('fr', _('French')),
        ],
        default='eng',

    )

    theme_preference = models.CharField(
        _("theme preference"),
        max_length=10,
        choices=[
            ('light', _('Light Theme')),
            ('dark', _("Dark theme")),
            ('system', _("System default"))
        ],

        default="system",
    )

    # group and user_persmision relationship
    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',  # Add this line
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_query_name='customuser',
    )

    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_set',
        blank=True,
        help_text='Specific permissions for this user.',
        related_query_name='customuser',
    )

    # model configuration

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [
        "fullname"
    ]

    # managers
    objects = CustomUserManager()
    query_manager = CustomUserQueryManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        ordering = ["-date_joined"]

    # methods in user model
    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.fullname

    def get_short_name(self):
        return self.username

    def clean(self):
        # for super class
        super().clean()

        if self.date_of_birth:
            from datetime import date
            today = date.today()
            age = today.year - self.date_of_birth.year - \
                ((today.month, today.day) <
                    (self.date_of_birth.month, self.date_of_birth.day))
            if age < 13:
                raise ValidationError(
                    _("You must be above 13 years old to register .."))

    def increment_failed_login(self):
        """increment failed login and potentially lock the account """
        self.failed_login_attempts += 1

        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + \
                timezone.timedelta(minutes=15)
            self.is_active = False

        self.last_failed_login = timezone.now()
        self.save()

    def unlock_account_if_locked(self):
        """unlock account before proceed after 15 minutes"""
        if self.is_account_locked() and self.account_locked_until <= timezone.now():
            self.is_active = True
            self.failed_login_attempts = 0
            self.account_locked_until = None
            self.save(update_fields=["is_active", "failed_login_attempts", "account_locked_until"])

    def reset_failed_login_attempts(self):
        """reset all field after successful login """

        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.is_active = True
        self.save()

    def is_account_locked(self):
        """check if the account is current locked"""
        if self.account_locked_until:
            return self.account_locked_until > timezone.now()

        return False

    def generate_email_confirmation_token(self):
        """email confirmation token generation logic"""
        token = token_urlsafe(20)
        self.email_confirmation_token = token
        self.save(update_fields=["email_confirmation_token"])
        return token

    def generate_password_reset_token(self):
        """password confirmation token"""
        token = token_urlsafe(20)
        self.password_reset_token = token
        self.save(update_fields=["password_reset_token"])
        return token

    # invalidating of confirmation token logic

    def invalidate_email_confirmation_token(self):
        self.email_confirmation_token = None
        self.save(update_fields=["email_confirmation_token"])

    def invalidate_password_confirmation_token(self):
        self.password_reset_token = None
        self.save(update_fields=["password_reset_token"])

    def process_profile_picture(self):
        """process profile picture after upload"""

        img = Image.open(self.profile_picture)
        img = img.convert("RGB")
        img.thumbnail((300, 300))  # resize to the maximum of 300 * 300
        img.save(self.profile_picture.path, format="JPEG", quality=85)

    def calculate_age(self):
        """calculate the user age based on the birth date"""
        if self.date_of_birth:
            from datetime import date
            today = date.today()
            return today.year - self.date_of_birth.year - (
                (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None

    def update_last_login_ip(self, ip_address):
        """Updated the users last login ip """

        self.last_login_ip = ip_address
        self.save(update_fields=["last_login_ip"])

    def clean_bio(self):
        """before saving the bio ,Cleans up the user's bio by removing extra spaces and unwanted characters."""
        if self.bio:
            self.bio = ' '.join(self.bio.split())
            self.save(update_fields=['bio'])

    def set_theme_preference(self, theme):
        """updates the user theme preferences"""
        if theme in ["light", "dark", "system"]:
            self.theme_preference = theme
            self.save(update_fields=["theme_preference"])

    def set_language_preference(self, language):
        """
        Updates the user's language preference.
        """
        if language in ["eng", "swa", "fr"]:
            self.language_preferences = language
            self.save(update_fields=["language_preferences"])

    def soft_delete(self):
        """Soft deletes the user account."""
        self.deleted_at = timezone.now()
        self.is_active = False
        self.save(update_fields=["deleted_at", "is_active"])