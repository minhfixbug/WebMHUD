from django.shortcuts import render, redirect # type: ignore
from .models import AddUser
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render
import re
import json

import tkinter as tk
from tkinter import messagebox

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth import SESSION_KEY

from rest_framework.response import Response
from rest_framework import status
from rest_framework.renderers import JSONRenderer

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
        user = AddUser.objects.get(Username=username)
        return user.Password
    except AddUser.DoesNotExist:
        return None

cipher = AESCipher(key)

def Login(request):
    if request.method == 'POST':
        username1 = request.POST.get('user2')
        password1 = request.POST.get('pass2')
        # username_enc = cipher.encrypt(username1)
        # password_enc = cipher.encrypt(password1)

        data = get_password_by_username(username1)
        data = eval(data)
        
        if data is not None:
            temp = cipher.decrypt(data)
            #ko decrypt đc 
            if temp == password1.encode():
                check_user = authenticate(request, username=username1, password=temp)
                auth_login(request, check_user)
                new_token = create_token_login(username1, password1)
                return redirect('loadingpage')
            else:
                messages.info(request, "Username or password incorrect!")
        else:
            messages.info(request, "Username or password incorrect!")

    return render(request, "LoginPage.html")

def custom_login(request, user):
    # Gán ID của người dùng vào session để đánh dấu người dùng đã đăng nhập
    request.session[SESSION_KEY] = user.pk

def custom_authenticate(username, password):
    try:
        # Tìm kiếm người dùng với tên người dùng được cung cấp
        user = AddUser.objects.get(Username=username)
        # Kiểm tra mật khẩu của người dùng
        if custom_check_password(password):
            # Trả về người dùng nếu mật khẩu đúng
            return user
    except AddUser.DoesNotExist:
        # Trả về None nếu không tìm thấy người dùng
        return None
    # Trả về None nếu mật khẩu không đúng
    return None

def custom_check_password(password):
    user = AddUser.objects.get(Password=password)
    if user is not None:
        return True
    else:
        return False

def Register(request):
    if request.method == 'POST':
        username = request.POST['user1']
        email = request.POST['email1']
        password = request.POST['pass1']
        confirmpassword = request.POST['cpass1']
        user_types = request.POST['user_type']

        if(is_valid_username(username) == True and is_valid_email(email) == True):
            if(is_valid_password(password, confirmpassword) == True):
                data=password
                password_enc=cipher.encrypt(data.encode('utf-8')).hex()
                user1 = AddUser(Username=username, Email=email, Password=password_enc)
                token = create_token(username, password, user_types)
                user1.save()
                print(token)
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

def create_token(username, password, user_types):
    encoded_username = username.encode()
    encoded_password = password.encode()
    encoded_user_types = user_types.encode()
    encrypted_username = cipher.encrypt(encoded_username)
    encrypted_password = cipher.encrypt(encoded_password)
    encrypted_user_types = cipher.encrypt(encoded_user_types)
    str_username = str(encrypted_username)
    str_password = str(encrypted_password)
    str_user_types = str(encrypted_user_types)

    # Tạo từ điển token
    token = {
        "username": str_username,
        "password": str_password,
        "user_types": str_user_types
    }

    # Chuyển từ điển thành chuỗi JSON
    token_json = json.dumps(token)

    return token_json

def create_token_login(username, password):
    encoded_username = username.encode()
    encoded_password = password.encode()
    encrypted_username = cipher.encrypt(encoded_username)
    encrypted_password = cipher.encrypt(encoded_password)
    str_username = str(encrypted_username)
    str_password = str(encrypted_password)

    # Tạo từ điển token
    token = {
        "username": str_username,
        "password": str_password,
    }
 
    # Chuyển từ điển thành chuỗi JSON
    # token_json = json.dumps(token)

    with open("token.json", "w") as file:
        json.dump(token, file)
