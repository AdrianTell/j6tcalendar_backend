from .models import Request, User
from .functions import verify_token_signature
from calendar_project import settings
from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from jwt.algorithms import RSAAlgorithm

class RequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = ['id', 'username', 'time_submitted', 'date_start',
            'date_end', 'all_day', 'status',
            'supervisor', 'reason', 'notes', 'denial_notes', 'authorized_by']

    def create(self, validated_data):
        supervisor = validated_data.pop('supervisor')
        request = Request.objects.create(**validated_data)
        request.supervisor.set(supervisor)
        request.save()
        return request

class CreateRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = ['username', 'date_start',
            'date_end', 'all_day',
            'supervisor', 'reason', 'notes']

class UpdateRequestStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = ['status', 'denial_notes']

class EditRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Request
        fields = ['date_start',
            'date_end', 'all_day',
            'supervisor', 'reason', 'notes']

class SupervisorSerializer(serializers.Serializer):
    username = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()

class UserSerializer(serializers.Serializer):
    username = serializers.EmailField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    is_staff = serializers.BooleanField()

class CreateUserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=True)
    password = serializers.CharField(max_length=32, required=True)
    first_name = serializers.CharField(max_length=52, required=True)
    last_name = serializers.CharField(max_length=64, required=True)

class SetAdminSerializer(serializers.Serializer):
    is_staff = is_staff = serializers.BooleanField(required=True)

class ForgotPasswordSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=True)

class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=32, required=True)
    new_password = serializers.CharField(max_length=32, required=True)

class CustomerTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['isAuthenticated'] = True
        token['isAdminUser'] = user.is_staff
        token['has_tempPassword'] = user.has_tempPassword
        return token

class SSOTokenObtainSerializer(serializers.Serializer):

    default_error_messages = {
        'no_active_account': 'No active accoutn found with the given credentials'
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['token'] = serializers.CharField()

    def validate(self, attrs):
        token = attrs['token']

        key_json = '{"kty": "RSA","alg": "RS256","use": "sig","kid": "_R_qf-cnHQVlVFd638gGU3C-xxNTsbusKb9D5cLHYmc","n": "wk8hmt+ZW+3dMzWoRYn36/s094E/XPXEA/vi5pZKxSuLX19Fg1LCIl8Rn63Y6eyNjZzSYjDKJn54NdmX8q6+J6pblmvQXo/o866Pkacc5oK1tWGdVZ3Q3jQX0q/THnBJonwVk18mHLF5vIhdVvFmlKrIWbnq1qoi3BRzU59zgbvgHVmn3KaVwYIUHgWDuvlF9BOSC0FyDX4Aad7bWfiGOe2UX02YN1H/wx7WwdRen6c3ahJisQNGZb/ZH2ddPNi5pSUYtFRVvMpN16NuN7q8T3bA+lvUQ6NsjD0p7d65zMGHrWgPoTyXFRWn0ql2hEZsdgeZYrmtnwOdES4xjfRcow==","e": "AQAB"}'

        public_key = RSAAlgorithm.from_jwk(str(key_json))

        #in case of signature error, it throws InvalidSignatureError (500)
        decoded_data = verify_token_signature(token, public_key, 'RS256')

        print(decoded_data)

        try:
            self.user = User.objects.get(username=decoded_data['email'])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )

        if self.user is None or not self.user.is_active:
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )

        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplementedError("Must implement 'get_token' method for 'TokenObtainSerializer' subclasses")

class SSOTokenObtainPairSerializer(SSOTokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        token = RefreshToken.for_user(user)
        token['username'] = user.username
        token['isAuthenticated'] = True
        token['isAdminUser'] = user.is_staff
        token['has_tempPassword'] = user.has_tempPassword
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        return data
    
