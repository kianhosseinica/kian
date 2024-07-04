from django.core.management.base import BaseCommand
from django.conf import settings
import requests
import logging

class Command(BaseCommand):
    help = 'Refresh the access token'

    def handle(self, *args, **options):
        url = 'https://cloud.lightspeedapp.com/oauth/access_token.php'
        payload = {
            'client_id': settings.CLIENT_ID,
            'client_secret': settings.CLIENT_SECRET,
            'refresh_token': settings.REFRESH_TOKEN,
            'grant_type': 'refresh_token'
        }
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            data = response.json()
            settings.ACCESS_TOKEN = data['access_token']
            logging.info('Access token refreshed successfully.')
        else:
            logging.error('Failed to refresh access token.')
            raise Exception('Failed to refresh token')
