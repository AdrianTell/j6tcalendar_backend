import jwt
import base64
from threading import Thread
from rest_framework import exceptions
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from calendar_project.calendar_app import serializers
from .models import User, Request
from django.forms.models import model_to_dict
from django.template.loader import render_to_string

def new_thread(function):
    def wrapper(*args, **kwargs):
        thread = Thread(target = function, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
    return wrapper

def verify_token_signature(token, key, algorithms):
    decode = jwt.decode(token, key, algorithms, audience='account')
    return decode

###################################

@new_thread
def calendar_send_confirmation_email(confirm_link, to):
    plain_content = render_to_string('confirmation_email.txt', {'confirm_link': confirm_link})
    htmly_content = render_to_string('confirmation_email.html', {'confirm_link': confirm_link})
    send_mail(
        'Confirm your email', 
        plain_content,
        'Spathe PTO Calendar',
        to,
        fail_silently=False,
        html_message=htmly_content
    )

@new_thread
def calendar_send_status_email(request):
    formatted_date_start = request.date_start
    formatted_date_end = request.date_end
    time_string = "from {0} to {1}".format(formatted_date_start, formatted_date_end)
    request_string = "Your Spathe PTO request {0} has been {1}".format(time_string, request.status)
    send_mail(
        'Your Spathe PTO request', 
        request_string,
        'Spathe PTO Calendar',
        (request.username,),
        fail_silently=False
    )

@new_thread
def calendar_send_email(subject, message, to):
    send_mail(
        subject, 
        message,
        'Spathe PTO Calendar',
        to,
        fail_silently=False
    )

def calendar_validate_email(email):
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False

def request_dict(request):
    serializer = serializers.RequestSerializer(request)
    data = serializer.data
    supervisors = request.supervisor.all()
    s_list = []
    for s in supervisors:
        s_dict = serializers.SupervisorSerializer(s).data
        s_list.append(s_dict)
    data['supervisor'] = s_list
    data['user'] = serializers.SupervisorSerializer(User.objects.get(username=data['username'])).data
    authorized_by_data = serializers.SupervisorSerializer(request.authorized_by).data
    data['authorized_by'] = authorized_by_data
    return data

def user_dict(user):
    serializer = serializers.UserSerializer(user)
    data = serializer.data
    return data       

def admin_count():
    all_admins = User.objects.all().filter(is_active=True, is_staff=True)
    return all_admins.count()
