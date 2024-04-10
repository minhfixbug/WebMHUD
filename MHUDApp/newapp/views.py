from django.shortcuts import render, redirect, HttpResponse # type: ignore
from .models import AddUser
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render
import re

import tkinter as tk
from tkinter import messagebox

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import sys

key = SHA256.new(b'this is my key for the AES code!').digest()

# Create your views here.

class AESCipher:
    def __init__(self, key):
        self.key = key
        self.block_size = AES.block_size

    def encrypt(self, data):
        # Ensure the data is in bytes
        if not isinstance(data, bytes):
            raise ValueError("Data must be in bytes.")
        data = pad(data, self.block_size)
        iv = AES.new(self.key, AES.MODE_CBC).iv
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(data)
        return iv + encrypted_text

    def decrypt(self, encrypted_text):
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(encrypted_text[self.block_size:]), self.block_size)
        return plaintext

def get_password_by_username(username):
    try:
        user = User.objects.get(username=username)
        return user.password
    except User.DoesNotExist:
        return None

cipher = AESCipher(key)

def Login(request):
    if request.method == 'POST':
        username1 = request.POST.get('user2')
        password1 = request.POST.get('pass2')

        check_user = authenticate(request, username=username1, password=password1)

        if check_user is not None:
            auth_login(request, check_user)

            return redirect('userpage')
        else:
            messages.info(request, "Username or password incorrect!")

    return render(request, "LoginPage.html")

def Register(request):
    if request.method == 'POST':
        username = request.POST['user1']
        email = request.POST['email1']
        password = request.POST['pass1']
        confirmpassword = request.POST['cpass1']

        if(is_valid_username(username) == True and is_valid_email(email) == True):
            if(is_valid_password(password, confirmpassword) == True):
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()
            else:
                message = is_valid_password(password, confirmpassword)
                messages.info(request, message)
        else:
            message = is_valid_username(username)
            if message is not True:
                messages.info(request, message)
            else:
                messages.info(request, "Email is incorrect format!")
        

    return render(request, "RegisterPage.html")


def is_valid_username(username):
    # Kiểm tra chiều dài của tên người dùng
    if len(username) < 5 or len(username) > 20:
        return False
    
    # Kiểm tra các ký tự đặc biệt không được phép trong tên người dùng
    special_characters = "!@#$%^&*()-_+=[]{}|\\;:'\"<>,.?/~"

    all_users = User.objects.all()

    # for user in all_users:
    #     print(user.username)

    for user in all_users:
        if username == user.username:
            return 'Username existed! Please choose other name'
        else:
            continue
    
    if any(char in special_characters for char in username):
        return 'Username cannot include special character!'
    
    # Kiểm tra xem tên người dùng chỉ chứa các ký tự chữ cái, số và dấu gạch dưới
    if not username.isalnum():
        return 'Username cannot include all character or number!'
    
    # Nếu không có vấn đề gì, tên người dùng được coi là hợp lệ
    return True

def is_valid_email(email):
    # Biểu thức chính quy để kiểm tra địa chỉ email
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    
    # Kiểm tra địa chỉ email với biểu thức chính quy
    if re.match(email_regex, email):
        return True
    else:
        return False

def is_valid_password(password1, password2):
    if password1.isdigit():
        return 'Password can not be all numbers!'
    if password1 != password2:
        return 'Password mismatch!'
    
    return True

def User1(request):
    return render(request, "UserPage.html")

def Admin(request):
    return render(request, "AdminPage.html")

def Load(request):
    return render(request, "LoadingPage.html")
