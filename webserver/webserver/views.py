from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from django.http import JsonResponse, HttpResponse
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import redirect

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie

from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout

from OpenSSL import crypto
import base64

from .core import generateToken, verifyTokenValid, getTokenInfo, getRefreshToken, generateTokenfromRefreshToken, revokeTokens, generateCert, revokeCert, verifyCert, getstatusCert

import logging
logger = logging.getLogger(__name__)

def index(request):
    return redirect('/static/index.html')

@method_decorator(ensure_csrf_cookie, name='post')
class AuthUserView(CreateAPIView):
    def post(self, request, *args, **kwargs):
        data=request.data 
        username=''
        password=''
        for key in data:          
            if key == 'username':
                username = data['username'] 
            if key == 'password':
                password = data['password']

        if username == '' or password == '':
            return JsonResponse({"description": 'username or password can not be NULL'}, status=406)  

        user = None
        try:
            u = User.objects.get(username=username)
        except User.DoesNotExist:
            u = None 

        if u != None:
            user = authenticate(username=username, password=password) 
            if user == None:
                return JsonResponse({"description": 'username or password is not valid'}, status=406)
        else:
            user = User.objects.create_user(username=username, password=password)
            if user == None:
                return JsonResponse({"description": 'can not create user'}, status=406)
            user.save()  

        access_token = generateToken(username) 

        login(request, user)    

        return JsonResponse({"access_token": access_token}, status=200)    

@method_decorator(ensure_csrf_cookie, name='post')
class LogoutUserView(CreateAPIView):
    def post(self, request, *args, **kwargs):
        data=request.data 
        token=None
        for key in data:          
            if key == 'token':
                token = data['token'] 

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406)     

        userinfo = getTokenInfo(token)     

        user = None
        try:
            user = User.objects.get(username=userinfo['username'])
        except User.DoesNotExist:
            user = None 
        if user == None:
            return JsonResponse({"description": 'username is not existed'}, status=406)

        logout(request)    

        return HttpResponse(status=200)  

@method_decorator(ensure_csrf_cookie, name='post')
class UpdateUserView(CreateAPIView):
    def post(self, request, *args, **kwargs):
        data=request.data 
        last_name=''
        first_name=''
        email=''
        token=None
        for key in data:          
            if key == 'last_name':
                last_name = data['last_name'] 
            if key == 'first_name':
                first_name = data['first_name']
            if key == 'email':
                email = data['email']    
            if key == 'token':
                token = data['token']    

        if last_name == '' or first_name == '' or email == '':
            return JsonResponse({"description": 'last_name or first_name or email can not be NULL'}, status=406)  
       
        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406)     

        userinfo = getTokenInfo(token)     

        user = None
        try:
            user = User.objects.get(username=userinfo['username'])
        except User.DoesNotExist:
            user = None 
        if user == None:
            return JsonResponse({"description": 'username is not existed'}, status=406)  

        user.last_name = last_name
        user.first_name = first_name
        user.email = email

        user.save(update_fields=['last_name', 'first_name', 'email'])         

        return HttpResponse(status=200)

@method_decorator(ensure_csrf_cookie, name='get')
class GetUserInfoView(CreateAPIView):
    """Authenticate user in the system"""
    def get(self, request, format=None):
        token = request.headers.get('Authorization')

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406) 

        userinfo = getTokenInfo(token)     

        user = None
        try:
            user = User.objects.get(username=userinfo['username'])
        except User.DoesNotExist:
            user = None 
        if user == None:
            return JsonResponse({"description": 'username is not existed'}, status=406)

        return JsonResponse({"last_name": user.last_name, "first_name": user.first_name, "email": user.email}, status=200)                       

@method_decorator(ensure_csrf_cookie, name='post')
class RefreshTokenView(CreateAPIView):
    def post(self, request, *args, **kwargs): 
        data=request.data  
        token = ''
        for key in data:
            if key == 'token' :
                token = data['token']

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)        
        
        refresh_token = getRefreshToken(token)
        if refresh_token == None:
            return JsonResponse({'description': 'refresh token is not eixisted. You have to re-authorize'}, status=406)
        else:
           return JsonResponse({'refresh_token': refresh_token})   

@method_decorator(ensure_csrf_cookie, name='post')
class NewTokenView(CreateAPIView):
    def post(self, request, *args, **kwargs): 
        data=request.data 
        refresh_token = ''
        for key in data:
            if key == 'refresh_token' :
                refresh_token = data['refresh_token']

        if refresh_token == None:
            return JsonResponse({"description": 'refresh_token is required'}, status=406)        
        
        new_token = generateTokenfromRefreshToken(refresh_token)
        if new_token == None:
            return JsonResponse({'description': 'token can not be generated. You have to re-authorize'}, status=406)
        else:
           return JsonResponse({'token': new_token})              

@method_decorator(ensure_csrf_cookie, name='post')          
class RevokeTokenView(CreateAPIView):
    def post(self, request, *args, **kwargs): 
        data=request.data 
        token = ''
        for key in data:
            if key == 'token' :
                token = data['token']  

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)           

        revokeTokens(token)

        return HttpResponse(status=200)

@method_decorator(ensure_csrf_cookie, name='post')
class GenerateCertView(CreateAPIView):
    def post(self, request, *args, **kwargs): 
        data=request.data 
        token = ''
        for key in data:
            if key == 'token' :
                token = data['token']  

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406) 

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406)                 

        userinfo = getTokenInfo(token) 

        user = None
        try:
            user = User.objects.get(username=userinfo['username'])
        except User.DoesNotExist:
            user = None 
        if user == None:
            return JsonResponse({"description": 'username is not existed'}, status=406)

        r, status= generateCert(user.username, user.email, user.password)
        archive = base64.b64decode(r['archive'])
        archive = crypto.load_pkcs12(archive, passphrase=user.password.encode())
        cert = crypto.dump_certificate(crypto.FILETYPE_PEM, archive.get_certificate())
        ca_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, archive.get_ca_certificates())
        priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, archive.get_privatekey())

        return JsonResponse({"uid": r['uid'], "cert": cert, "ca_certs": ca_cert, "priv": priv}, status=status)    

@method_decorator(ensure_csrf_cookie, name='post')
class VerifyCertView(APIView):
    parser_classes = (MultiPartParser, FormParser,)
    def post(self, request, format=None): 
        data=self.request.data 
        if self.request.FILES == None:
            return JsonResponse({"description": 'No pem file'}, status=406)

        token = ''
        for key in data:
            if key == 'token' :
                token = data['token']  

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406)                  

        r, status = verifyCert(self.request.FILES['certificate'])

        return JsonResponse(r, status=status)         

@method_decorator(ensure_csrf_cookie, name='post')
class RevokeCertView(CreateAPIView):
    def post(self, request, *args, **kwargs): 
        data=request.data 
        token = ''
        for key in data:
            if key == 'token' :
                token = data['token']  

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406) 

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406)                 

        userinfo = getTokenInfo(token) 

        user = None
        try:
            user = User.objects.get(username=userinfo['username'])
        except User.DoesNotExist:
            user = None 
        if user == None:
            return JsonResponse({"description": 'username is not existed'}, status=406)

        r, status= revokeCert(user.username)

        return JsonResponse(r, status=status)      

@method_decorator(ensure_csrf_cookie, name='get')
class StatusCertView(CreateAPIView):
     def get(self, request, format=None):
        token = request.headers.get('Authorization')

        if token == None:
            return JsonResponse({"description": 'token is required'}, status=406)

        if verifyTokenValid(token) == False:
            return JsonResponse({"description": 'token is expired'}, status=406)             

        userinfo = getTokenInfo(token) 

        if userinfo['username'] != "admin":
            return JsonResponse({"description": 'you are not allowed to get the status information of certificates'}, status=406)

        r, status= getstatusCert()

        return JsonResponse(r, status=status)                      
