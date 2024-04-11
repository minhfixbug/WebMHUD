from django. urls import path # type: ignore
from . import views
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path("login/", views.Login, name="loginpage"),
    path("register/", views.Register, name="registerpage"),
    path("user/", views.User1, name="userpage"),
    path("admin/", views.Admin, name="adminpage"),
    path("load/", views.Load, name="loadingpage"),
    path('token/', obtain_auth_token)
]
