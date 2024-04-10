from django. urls import path # type: ignore
from . import views

urlpatterns = [
    path("login/", views.Login, name="loginpage"),
    path("register/", views.Register, name="registerpage"),
    path("user/", views.User1, name="userpage"),
    path("admin/", views.Admin, name="adminpage"),
    path("load/", views.Load, name="loadingpage")
]
