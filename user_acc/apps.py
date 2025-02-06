from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'user_acc'

    def ready(self):
        print("AccountsConfig ready method called!")  # Debug print
        import user_acc.signals