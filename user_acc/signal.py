import contextlib
import logging
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

CustomUser = get_user_model()

@receiver(post_save, sender=CustomUser)
def handle_new_user_creation(sender, instance, created, **kwargs):
    """
    Create a default profile or perform actions when a new user is created.
    
    This signal handler:
    - Sends a welcome email to new users
    - Could trigger initial profile creation
    - Logs user creation event
    """
    if created:
        # Send welcome email
        try:
            send_mail(
                'Welcome to Our Platform',
                f'Hi {instance.full_name},\n\n'
                'Thank you for registering! '
                'We\'re excited to have you join our community.',
                settings.DEFAULT_FROM_EMAIL,
                [instance.email],
                fail_silently=True,
            )
        except Exception as e:
            logger.error(
              f"Failed to send welcome email to {instance.email}:{str(e)}" ,
              extra={
                  'user_id': instance.id,
                  'user_email': instance.email
              } 
            )
            
@receiver(pre_save, sender=CustomUser)
def handle_account_status_changes(sender, instance, **kwargs):
    """
    Manage account status changes and related logic.
    
    This signal handler:    
    - Tracks failed login attempts
    - Implements account locking mechanism
    - Logs significant account status changes
    """
    # Only proceed if this is an existing user being updated
    if not instance.pk:
        return
    #loading the older instance with instance.pk
    with contextlib.suppress(CustomUser.DoesNotExist):
        old_instance = CustomUser.objects.get(pk=instance.pk)

        # Track failed login attempts
        if instance.failed_login_attempts > old_instance.failed_login_attempts:
            # Check if failed attempts exceed threshold
            if instance.failed_login_attempts >= 5:
                # Lock the account
                instance.account_locked_until = timezone.now() + timezone.timedelta(minutes=15)
                instance.is_active = False

            # Optional: Send security alert
            try:
                send_mail(
                    'Security Alert: Multiple Login Attempts',
                    'Multiple failed login attempts have been detected on your account. '
                    'If this was not you, please reset your password or contact support.',
                    settings.DEFAULT_FROM_EMAIL,
                    [instance.email],
                    fail_silently=True,
                )
            except Exception as e:
                logger.error(
                    f"Security alert email failed to  {instance.email}:{str(e)}" ,
                    extra={
                     'user_id': instance.id,
                     'user_email': instance.email
                    } 
                )   
        # Check for account unlock
        if (old_instance.is_active is False and 
            instance.is_active is True and 
            instance.failed_login_attempts < 5):
            # Reset lock status
            instance.account_locked_until = None
            instance.failed_login_attempts = 0
        
@receiver(pre_save, sender=CustomUser)
def normalize_user_data(sender, instance, **kwargs):
    """
    Normalize and validate user data before saving.
    
    This signal handler:
    - Ensures consistent data formatting
    - Performs additional validation
    """
    # Normalize email
    if instance.email:
        instance.email = instance.email.strip().lower()
    
    # Normalize username
    if instance.username:
        instance.username = instance.username.strip().lower()
    
    # Additional validation checks can be added here
    if instance.date_of_birth:
        # Ensure date of birth is not in the future
        if instance.date_of_birth > timezone.now().date():
            raise ValueError("Date of birth cannot be in the future")


@receiver(post_save, sender=CustomUser)
def verify_email_on_first_login(sender, instance, **kwargs):
    """
    Automatically verify user email on first successful login.
    
    This signal handler:
    - Marks user as verified on first login
    - Could trigger additional first-login actions
    """
    if (instance.is_verified is False and 
        instance.last_login is not None and 
        not hasattr(instance, '_email_verified_signal_processed')):

        instance._email_verified_signal_processed = True
        instance.is_verified = True
        #instance.verified_at = timezone.now()
        instance.save(update_fields=['is_verified',])




