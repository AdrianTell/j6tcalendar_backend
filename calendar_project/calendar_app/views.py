import json, base64

from django.utils.crypto import get_random_string

from django.db import IntegrityError

from rest_framework.generics import GenericAPIView
from rest_framework.decorators import api_view, permission_classes
from django.http import HttpResponse, JsonResponse
from calendar_project.calendar_app import serializers

from django.forms.models import model_to_dict
from django.shortcuts import redirect

from rest_framework.permissions import IsAdminUser, IsAuthenticated

from .models import Request, User
from .functions import calendar_send_email, calendar_send_status_email, calendar_validate_email, request_dict, calendar_send_confirmation_email, admin_count, user_dict

from rest_framework.parsers import JSONParser

from rest_framework_simplejwt.views import TokenObtainPairView

from calendar_project import settings

#Admin
class GetAllRequests(GenericAPIView):
    permission_classes = (IsAdminUser,)
    def get(self, request):
        r_list = Request.objects.all()
        s_list = []
        for r in r_list:
            s_list.append(request_dict(r))
        return JsonResponse({"requests":s_list}, status=200)

#Admin
class GetAllRequestsSorted(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request, status):
        r_list = Request.objects.all()
        s_list = []
        for r in r_list:
            if status.isalpha() and r.status.lower() == status.lower():
                s_list.append(request_dict(r))
        return JsonResponse({"requests":s_list}, status=200)

#Login
class CreateRequest(GenericAPIView):
    serializer_class = serializers.CreateRequestSerializer
    permission_classes = (IsAuthenticated,)
    def post(self, request, format=None):
        data = JSONParser().parse(request)
        try:
            if User.objects.get(username=data['username']).is_superuser:
                return HttpResponse('Superusers are not allowed to create PTO requests', status=400)
            serializer = serializers.RequestSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                calendar_send_email('A Spathe PTO request has been created', data['username'] + ' has created a PTO request and set you as one of its supervisors.', data['supervisor']) 
                return HttpResponse('Success!', status=200)
            return HttpResponse('Invalid,', status=400) 
        except KeyError:
            return HttpResponse('Incomplete Request', status=400)

#Admin
class SingleRequest(GenericAPIView):
    permission_classes = (IsAdminUser,)

    def get(self, request, dt):
        r = Request.objects.get(id=dt)
        dict_r = request_dict(r)
        return JsonResponse(dict_r, status=200)

    def delete(self, request, dt, format=None):
        r_request = Request.objects.get(id=dt)
        r_request.delete()
        return HttpResponse('Success!', status=200)
  
#Admin
class UpdateRequestStatus(GenericAPIView):
    serializer_class = serializers.UpdateRequestStatusSerializer
    permission_classes = (IsAdminUser,)

    def put(self, request, dt):
        r_request = Request.objects.get(id=dt)
        data = JSONParser().parse(request)
        if request.user not in r_request.supervisor.all():
            return HttpResponse('Only supervisors are allowed to authorize respective requests.', status=400)
        try:
            r_request.status = data["status"]
            r_request.authorized_by = request.user
            if "denial_notes" in data:
                r_request.denial_notes = data["denial_notes"]
            r_request.save()
        except KeyError:
            return HttpResponse('Incomplete Request.', status=400)

        calendar_send_status_email(r_request)
        return HttpResponse('Success!', status=200)

#Login
class EditRequest(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.EditRequestSerializer

    def put(self, request, dt):
        r_request = Request.objects.get(id=dt)
        data = JSONParser().parse(request)

        if request.user.username != r_request.username:
            return HttpResponse('Users can only edit their own requests.', status=400)
        
        if 'date_start' in data:
            r_request.date_start = data['date_start']
        if 'date_end' in data:
            r_request.date_end = data['date_end']
        if 'all_day' in data:
            r_request.all_day = data['all_day']
        try:
            if 'supervisor' in data:
                r_request.supervisor.set(data['supervisor'])
        except IntegrityError:
            return HttpResponse('Invalid Supervisor', status=400)
        if 'reason' in data:
            r_request.reason = data['reason']
        if 'notes' in data:
            r_request.notes = data['notes']
        
        r_request.status = 'Pending'
        r_request.save()
        return HttpResponse('Success!', status=200)

#Login
class GetUserRequests(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        r_list = Request.objects.filter(username=request.user.username)
        s_list = []
        for r in r_list:
            s_list.append(request_dict(r))
        return JsonResponse({"requests":s_list}, status=200)

#Admin
class GetAllUsers(GenericAPIView):
    permission_classes = (IsAdminUser,)
    def get(self, request):
        r_list = User.objects.all()
        s_list = []
        for r in r_list:
            if r.is_active:
                s_list.append(user_dict(r))
        return JsonResponse({'users':s_list}, status=200)

#Unprotected
class CreateUser(GenericAPIView):
    serializer_class = serializers.CreateUserSerializer
    def post(self, request, format=None):
        data = JSONParser().parse(request)
        try:
            if not calendar_validate_email(data['username']):
                return HttpResponse('Invalid Email (Username)', status=400)
            new_user = User(username=data["username"])
            new_user.set_password(data["password"])
            new_user.first_name = data["first_name"]
            new_user.last_name = data["last_name"]
            new_user.is_active = False
            user_code = User.objects.make_random_password()
            new_user.confirmation_code = user_code
            new_user.save()
            data = base64.urlsafe_b64encode(json.dumps({
                'username': new_user.username,
                'code': user_code
            }).encode()).decode()
            confirm_link = settings.BASE_URL + "/api/v1/user/confirm_email/{0}".format(data)
            calendar_send_confirmation_email(confirm_link, (new_user.username,))
        except KeyError:
            return HttpResponse("Incomplete Request", status=400) 
        return HttpResponse("Success!", status=200)

#Unprotected
class CreateUserDefinitive(GenericAPIView):
    def get(self, request, data):
        r_data = json.loads(base64.urlsafe_b64decode(data.encode()).decode())
        r_user = User.objects.get(username=r_data['username'])
        if r_data['code'] == r_user.confirmation_code and not r_user.is_active:
            r_user.is_active = True
            r_user.confirmation_code = ""
            r_user.save()
            response = redirect(settings.FE_URL)
            return response
        return HttpResponse('ERROR', status=400)

#Unprotected
class ResendConfirmationEmail(GenericAPIView):
    serializer_class = serializers.ForgotPasswordSerializer
    def put(self, request, username):
        data = JSONParser().parse(request)
        try:
            r_user = User.objects.get(username=username)
            if not r_user.is_active and r_user.confirmation_code:
                data = base64.urlsafe_b64encode(json.dumps({
                    'username': r_user.username,
                    'code': r_user.confirmation_code
                }).encode()).decode()
                confirm_link = settings.BASE_URL + "/api/v1/user/confirm_email/{0}".format(data)
                calendar_send_confirmation_email(confirm_link, (r_user.username,))
                return HttpResponse('Success!', status=200)
            else:
                return HttpResponse('User is already activated', status=400)
        except KeyError:
            return HttpResponse("Incomplete Request", status=400)

#Admin
class SingleUser(GenericAPIView):
    permission_classes = (IsAdminUser,)

    def get(self, request, username, format=None):
        r_user = User.objects.get(username=username)
        dict_r = user_dict(r_user)
        return JsonResponse(dict_r, status=200)

    def delete(self, request, username, format=None):
        r_user = User.objects.get(username=username)
        r_user.is_active = False
        r_user.save()
        return HttpResponse('Success!', status=200)

#Admin
class SetAdminUser(GenericAPIView):
    permission_classes = (IsAdminUser,)
    serializer_class = serializers.SetAdminSerializer
    def put(self, request, username):
        data = JSONParser().parse(request)
        try:
            if not data['is_staff']:
                if admin_count() < 2:
                    return HttpResponse('There must be at least one active admin at all times.', status=400)
            r_user = User.objects.get(username=username)
            r_user.is_staff = data['is_staff']
            r_user.save()
        except KeyError:
            return HttpResponse("Incomplete Request", status=400) 
        return HttpResponse("Success!", status=200)

#Unprotected
class ForgotPassword(GenericAPIView):
    serializer_class = serializers.ForgotPasswordSerializer
    def post(self, request, format=None):
        data = JSONParser().parse(request)
        try:
            if not calendar_validate_email(data['username']):
                return HttpResponse('Invalid Email (Username)', status=400)
            r_user = User.objects.get(username=data['username'])
            temp_password = User.objects.make_random_password()
            r_user.set_password(temp_password)
            r_user.has_tempPassword = True
            calendar_send_email('Your Spathe Calendar temporary password', 'Your new temporary password is: ' + temp_password, (r_user.username,))
            r_user.save()
        except KeyError:
            return HttpResponse("Incomplete Request", status=400) 
        return HttpResponse("Success!", status=200)

# #Unprotected
# class SecureForgotPassword(GenericAPIView):
#     serializer_class = serializers.ForgotPasswordSerializer
#     def post(self, request, format=None):
#         data = JSONParser().parse(request)
#         try:
#             if not calendar_validate_email(data['username']):
#                 return HttpResponse('Invalid Email (Username)', status=400)
#             r_user = User.objects.get(username=data['username'])
#             first_half_temp_password = User.objects.make_random_password(6)
#             second_half_temp_password = User.objects.make_random_password(6)
#             r_user.set_password(first_half_temp_password + second_half_temp_password)
#             r_user.has_tempPassword = True
#             calendar_send_email('Your Spathe Calendar temporary password', 'The second half of your temporary password is: ' + second_half_temp_password, (r_user.username,))
#             r_user.save()
#         except KeyError:
#             return HttpResponse("Incomplete Request", status=400) 
#         return JsonResponse({'first_half':first_half_temp_password}, status=200)

#Login
class ChangePassword(GenericAPIView):
    serializer_class = serializers.ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)
    def post(self, request, format=None):
        data = JSONParser().parse(request)
        try:
            if not calendar_validate_email(request.user.username):
                return HttpResponse('Invalid Email (Username)', status=400)
            r_user = request.user

            if not r_user.has_tempPassword and not r_user.check_password(data['password']):
                return HttpResponse('Wrong password', status=400)

            r_user.set_password(data['new_password'])
            r_user.has_tempPassword = False
            r_user.save()

        except KeyError:
            return HttpResponse("Incomplete Request", status=400) 
        return HttpResponse("Success!", status=200)

#CustomTokenView
#Unprotected
class CustomTokenObtainView(TokenObtainPairView):
    serializer_class = serializers.CustomerTokenObtainPairSerializer

#SSOTokenView
class SSOTokenView(TokenObtainPairView):
    serializer_class = serializers.SSOTokenObtainPairSerializer



@api_view(['GET'])
def NiceView(GenericAPIView):
    return HttpResponse(':)', status=200)

@api_view(['GET'])
@permission_classes((IsAuthenticated,))
def ProtectedNice(GenericAPIView):
    return HttpResponse(':)', status=200)

@api_view(['GET'])
@permission_classes((IsAdminUser,))
def AdminNice(GenericAPIView):
    return HttpResponse(':)', status=200)


#Login
class GetAllSupervisors(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        r_list = User.objects.all()
        s_list = []
        for r in r_list:
            if r.is_active and r.is_staff and not r.is_superuser:
                s_list.append(user_dict(r))
        return JsonResponse({'supervisors':s_list}, status=200)