from django.conf.urls import include, url
from django.urls import path
from django.contrib import admin
from rest_framework import permissions
from rest_framework.decorators import api_view
from calendar_project.calendar_app import views

from rest_framework_simplejwt import views as jwt_views

from drf_yasg import openapi
from drf_yasg.views import get_schema_view

swagger_info = openapi.Info(
    title="Calendar API",
    default_version='v1',
    description="Backend API for the calendar"
)

SchemaView = get_schema_view(
    public=True,
    permission_classes=(permissions.AllowAny,),
)


# urlpatterns required for settings values
required_urlpatterns = [
    url(r'^swagger(?P<format>.json|.yaml)$', SchemaView.without_ui(cache_timeout=0), name='schema-json'),
    url(r'^swagger/$', SchemaView.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    url(r'^redoc/$', SchemaView.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    #path('api/v1/token/', jwt_views.TokenObtainPairView.as_view()),
    #path('api/v1/token/refresh/', jwt_views.TokenRefreshView.as_view()),
    path('api/v1/token/', views.CustomTokenObtainView.as_view()),
    path('api/v1/sso_token/', views.SSOTokenView.as_view()),
]

urlpatterns = [
    path('api/v1/request/all/', views.GetAllRequests.as_view()),
    path('api/v1/request/all_sorted/<status>', views.GetAllRequestsSorted.as_view()),
    path('api/v1/request/create/', views.CreateRequest.as_view()),
    path('api/v1/request/<dt>', views.SingleRequest.as_view()),
    path('api/v1/request/updatestatus/<dt>', views.UpdateRequestStatus.as_view()),
    path('api/v1/request/edit/<dt>', views.EditRequest.as_view()),

    path('api/v1/user/requests/', views.GetUserRequests.as_view()),
    path('api/v1/user/all/', views.GetAllUsers.as_view()),
    path('api/v1/user/create/', views.CreateUser.as_view()),
    path('api/v1/user/<username>', views.SingleUser.as_view()),
    path('api/v1/user/set_admin/<username>', views.SetAdminUser.as_view()),
    path('api/v1/user/forgot_password/', views.ForgotPassword.as_view()),
    path('api/v1/user/change_password/', views.ChangePassword.as_view()),

    path('api/v1/user/confirm_email/<data>', views.CreateUserDefinitive.as_view()),
    path('api/v1/user/resend_confirm_email/<username>', views.ResendConfirmationEmail.as_view()),

    path('api/v1/supervisor/all/', views.GetAllSupervisors.as_view()),

    path('api/v1/nice', views.NiceView),
    path('api/v1/protected_nice', views.ProtectedNice),
    path('api/v1/admin_nice', views.AdminNice),
] + required_urlpatterns