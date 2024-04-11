from django.shortcuts import render, redirect 
from .models import AddUser
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render
import re
import json

from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth import SESSION_KEY


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

key = SHA256.new(b'this is my key for the AES code!').digest()

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

        data = get_password_by_username(username1)
        data = eval(data)

        user_type = get_user_types(username1)
        
        if data is not None:
            temp = cipher.decrypt(data)
            if temp == password1.encode():
                check_user = authenticate(request, username=username1, password=temp)
                auth_login(request, check_user)
                create_token_login(username1, password1, user_type)
                return redirect('loadingpage')
            else:
                messages.info(request, "Username or password incorrect!")
        else:
            messages.info(request, "Username or password incorrect!")

    return render(request, "LoginPage.html")

def get_user_types(username):
    try:
        user = AddUser.objects.get(Username=username)
        return user.User_types
    except AddUser.DoesNotExist:
        return None

def custom_login(request, user):
    request.session[SESSION_KEY] = user.pk

def custom_authenticate(username, password):
    try:
        user = AddUser.objects.get(Username=username)
        if custom_check_password(password):
            return user
    except AddUser.DoesNotExist:
        return None
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
                password_enc=cipher.encrypt(data.encode())
                user1 = AddUser(Username=username, Email=email, Password=password_enc, User_types=user_types)
                create_token(username, password, user_types)
                user1.save()
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
    if len(username) < 5 or len(username) > 20:
        return False
    
    special_characters = "!@#$%^&*()-_+=[]{}|\\;:'\"<>,.?/~"

    all_users = User.objects.all()

    for user in all_users:
        if username == user.username:
            return 'Username existed! Please choose other name'
        else:
            continue
    
    if any(char in special_characters for char in username):
        return 'Username cannot include special character!'
    
    if not username.isalnum():
        return 'Username cannot include all character or number!'
    
    return True

def is_valid_email(email):
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    
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

    with open("token.json", "w") as file:
        json.dump(token, file)


def create_token_login(username, password, user_type):
    encoded_username = username.encode()
    encoded_password = password.encode()
    encrypted_username = cipher.encrypt(encoded_username)
    encrypted_password = cipher.encrypt(encoded_password)
    str_username = str(encrypted_username)
    str_password = str(encrypted_password)

    token = {
        "username": str_username,
        "password": str_password,
        "user_types": user_type
    }


    with open("token.json", "w") as file:
        json.dump(token, file)

def API(request):
    return render(request)

def testAPI(request):
    return render(request, "index.html")