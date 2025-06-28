import jwt
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth.models import User

def jwt_required(view_func):
    def wrapper(request, *args, **kwargs):
        token = None

        # Check Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            # Fallback: check cookie
            token = request.COOKIES.get('jwt_token')

        if not token:
            return JsonResponse({'error': 'Unauthorized'}, status=401)

        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            user = User.objects.get(id=payload['user_id'])
            request.user = user
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return JsonResponse({'error': 'Invalid or expired token'}, status=401)

        return view_func(request, *args, **kwargs)
    return wrapper
