import uuid

from datetime import datetime

from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    id = models.UUIDField(default=uuid.uuid4, editable=False)
    username = models.EmailField(primary_key=True)
    has_tempPassword = models.BooleanField(default=False)
    confirmation_code = models.CharField(max_length=150)

# Create your models here.
class Request(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=200)
    time_submitted = models.DateTimeField(auto_now_add=True, editable=False)
    date_start = models.CharField(max_length=100)
    date_end = models.CharField(max_length=100)
    all_day = models.BooleanField(default=True)
    status = models.CharField(max_length=10, default="Pending")
    supervisor = models.ManyToManyField(User, related_name='supervisor')
    reason = models.CharField(max_length=100)
    notes = models.TextField(max_length=255, null=True) #DOESNT LIKE WHEN ITS ""
    denial_notes = models.TextField(max_length=255, null=True)
    authorized_by = models.ForeignKey(User, null=True, on_delete=models.CASCADE, related_name='authorized_by')


