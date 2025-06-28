

# Create your views here.
# accounts/views.py

# accounts/views.py (continued)

from django.shortcuts import render,redirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate
from django.http import JsonResponse, HttpResponse
import jwt, datetime
from django.conf import settings
import json

from .auth import jwt_required
from django.http import JsonResponse




@csrf_exempt
def login_view(request):
    if request.method == 'GET':
        return render(request, 'accounts/login.html')  # Renders the form

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)

        if user is None:
            return HttpResponse('Invalid credentials', status=401)

        payload = {
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=settings.JWT_EXP_DELTA_SECONDS),
            'iat': datetime.datetime.utcnow(),
        }

        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        # # For now, just show token in response
        # return HttpResponse(f'JWT Token: {token}')
        print(f"JWT Token Set in Cookie: {token}")
        response = redirect('protected')  # <- name of the URL pattern
        response.set_cookie('jwt_token', token, httponly=True)
        return response

    return JsonResponse({'token': token})




@csrf_exempt
@jwt_required
def protected_view(request):
    print(f"Authenticated user: {request.user.username}")
    return JsonResponse({'message': f'Hello {request.user.username}, you are authenticated!'})


# @jwt_required
# def protected_view(request):
#     return JsonResponse({'message': f'Hello {request.user.username}, you are authenticated!'})