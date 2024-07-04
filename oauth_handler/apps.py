from django.apps import AppConfig
from django.core.management import call_command
class OauthHandlerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'oauth_handler'

    def ready(self):
        # Automatically refresh the token when the server starts
        call_command('refresh_token')