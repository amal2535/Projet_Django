from django.shortcuts import redirect
import re

class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        excluded_paths = [
            '/login',
            '/register',
            '/',
            '/password-reset/',
            '/resend-otp',
            '/admin/', 
        ]

        # Check if the path starts with any of the excluded paths
        is_excluded = any(request.path.startswith(path) for path in excluded_paths)

        # Regular expressions for specific paths
        is_verify_email = re.match(r'^/verify-email/.+$', request.path)
        is_reset_password = re.match(r'^/reset-password/.*/.*/$', request.path)

        if not request.user.is_authenticated and not (is_excluded or is_verify_email or is_reset_password):
            return redirect('/login')

        response = self.get_response(request)
        return response
