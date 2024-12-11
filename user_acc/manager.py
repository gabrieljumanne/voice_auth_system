from django.contrib.auth.models import BaseUserManager
from django.utils import timezone
from django.db import models
from django.db.models import Q, Count, Avg, Prefetch
from django.utils.translation import gettext_lazy as _
from typing import Optional, List, Dict, Any
from functools import lru_cache

class CustomUserManager(BaseUserManager):
    """
    Custom manager for CustomUser for user creation methods 
    """
    
    def create_user(
        self,
        email: str,
        username:str,
        fullname:str,
        password: Optional[str]= None,
        **extra_fields
    )->'CustomUser':
        """create and save the user with given email, username, fullname, password"""
        
        if not email:
            raise ValueError(_("user must have an email address"))
        if not username:
            raise ValueError(_("User must have a username"))
        if not fullname:
            raise ValueError(_("User must have the full name "))
        
        # processing the user email and username 
        email = self.normalize_email(email)
        username = username.strip().lower()
        
        user = self.model(
            email=email,
            username=username,
            fullname=fullname,
            **extra_fields
        )
        
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
            
        user.save(using=self._db)
        return user
    
    def create_superuser(
        self,
        email: str,
        username: str,
        fullname: str,
        password: str,
        **extra_fields
    )->'CustomUser':
        """creating a superuser using email, username, fullname, password"""

        #for superuser
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError ("Superuser must have is_superuser=True")
        
        return self.create_user(
            email=email,
            username=username,
            fullname=fullname,
            password=password,
            **extra_fields
        )


class CustomUserQueryManager:
    """Advanced query manager for CustomUser with comprehensive filtering and analysis method"""
    
    @classmethod
    @lru_cache(maxsize=128)
    def get_active_users(cls, days: int = 30)->models.QuerySet:
        """
        Retrieve  all users who have login within specified number of days 

        Args:
            Cls (_type_): method belongs to the class-level
            days (int, optional): Number of days to consider for activity. Defaults to 30.

        Returns:
            models.QuerySet: For active users 
        """
        threshold_date = timezone.now - timezone.timedelta(days=days)
        return CustomUser.objects.filter(
            is_active=True,
            last_login__gte =threshold_date
        )
        
    @classmethod
    def get_users_by_registration_period(
        cls,
        start_date : Optional[timezone.datetime] = None,
        end_date: Optional[timezone.datetime] = None,
    )->models.QuerySet:
        """Retrieve registered within specific period of date (time)

        Args:
            Cls:this method belongs to the class level
            start_date (Optional[timezone.datetime], optional): Start for registration period. Defaults to None.
            end_date (Optional[timezone.datetime], optional): End for registration period. Defaults to None.

        Returns:
            models.QuerySet: Queryset for users registered in specified date 
        """
        
        query = Q(is_active=True)
        
        if start_date:
            query &= Q(date_joined__gte=start_date)
        if end_date:
            query &= Q(date_joined__lte = end_date)
            
        return CustomUser.objects.filter(query)
        
    @classmethod
    def get_user_engagement_stats(cls)->Dict[str, Any]:
        """Compute user engagement statics 

        Args:
            Cls (): Method belongs to class-level

        Returns:
            Dict[str, Any]: Dictionary contain various engagement metrics 
        """
        return {
            'total_users': CustomUser.objects.count(),
            'active_users': cls.get_active_users().count(),
            'verified_users': CustomUser.objects.filter(is_verified=True).count(),
            'average_login_attempts': CustomUser.objects.aggregate(
                avg_attempts = Avg('failed_login_attempts')
            )['avg_attempts'],
            'language_distribution': list(
                CustomUser.objects.values('language_preferences')\
                    .annotate(count= Count('id'))\
                    .orderby("-count")
            ),
            'theme_preferences': list(
                CustomUser.objects.values('theme_preference')\
                    .annotate(count=Count('id'))\
                    .orderby('-count')
                
            ),
            
        }
        
    @classmethod
    def search_users(
            cls,
            query: str,
            search_fields: Optional[List[str]] = None
        )->models.QuerySet:
        """
        performing comprehensive user search across the fields
        Args:
            Cls (_type_): Method belongs to the class level
            query (str): Search item
            search_fields (Optional[List[str]], optional): field to search. Defaults to None.

        Returns:
            models.QuerySet: Queryset of the matching users 
        """
        search_fields = search_fields or ['email', 'username', 'fullname']
        
        #Q-objects of each search_fields
        search_query = Q()
        for field in search_fields:
            #filtering logic 
            search_query |= Q(**{f'{field}__icontains': query}) 
        
        return CustomUser.objects.filter(search_query)
    
    @classmethod
    def get_locked_accounts(cls)->models.QuerySet:
        """get all the locked account

        Args:
            Cls (_type_): Belong to the class level 

        Returns:
            models.QuerySet:returns all the locked account
        """
        return CustomUser.objects.filter(
            Q(account_locked_until__gt = timezone.now)|
            Q(is_active= False, failed_login_attempts__gte=5)
        )
        
    @classmethod
    def get_users_by_age_group(
        cls,
        min_age: Optional[int] = None,
        max_age: Optional[int] = None,
    )->models.QuerySet:
        """Retrieve users by there age group 

        Args:
            Cls (_type_): Belong to the class level
            min_age (Optional[int], optional): Minimum age for the users. Defaults to None.
            max_age (Optional[int], optional): Maximum age for the users   Defaults to None.

        Returns:
            models.QuerySet: users with the specified age group 
        """
        from datetime import date
        
        today = date.today()
        query = Q()
        
        if min_age is not None:
            min_birth_date = date(
                today.year - min_age - 1,
                today.month,
                today.day
            )
            query &= Q(date_of_birth__lt=min_birth_date)

        if max_age is not None:
            max_birth_date = date(
                today.year - max_age,
                today.month,
                today.day
            )
            query &= Q(date_of_birth__gt=max_birth_date)

        return CustomUser.objects.filter(query).exclude(date_of_birth__isnull=True)
