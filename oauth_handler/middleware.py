from django.shortcuts import redirect
from django.urls import reverse

class AuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.session.get('authenticated', False) and not request.path.startswith(reverse('enter_password')):
            return redirect('enter_password')
        response = self.get_response(request)
        return response
