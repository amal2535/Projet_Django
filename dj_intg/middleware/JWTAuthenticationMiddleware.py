from django.utils.deprecation import MiddlewareMixin
import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        token = request.COOKIES.get('jwt')
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                user = get_user_model().objects.get(id=payload['user_id'])
                request.user = user
            except jwt.ExpiredSignatureError:
                pass
            except jwt.InvalidTokenError:
                pass
