from django.shortcuts import render, redirect, HttpResponse
from .models import AddUser
from django.contrib.auth.models import User
from django.contrib import messages

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout

# Create your views here.

def Login(request):
    if request.method == 'POST':
        username1 = request.POST.get('user2')
        password1 = request.POST.get('pass2')

        check_user = authenticate(request, username=username1, password=password1)

        if check_user is not None:
            auth_login(request, check_user)

            return redirect('userpage')
        else:
            print("sai mk tk")

    return render(request, "LoginPage.html")

def Register(request):
    if request.method == 'POST':
        username = request.POST['user1']
        email = request.POST['email1']
        password = request.POST['pass1']
        # confirmpassword = request.POST['cpass1']

        user = User.objects.create_user(username=username, email=email, password=password)
        
        user.save()

    return render(request, "RegisterPage.html")

def User1(request):
    return render(request, "UserPage.html")

def Admin(request):
    return render(request, "AdminPage.html")