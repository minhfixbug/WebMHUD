from django.db import models
from django.contrib.auth.models import User
from django import forms
from django.contrib.auth.forms import UserCreationForm
from typing import Any, Dict

# Create your models here.
class AddUser(models.Model):
    Username = models.CharField(max_length=100,null=False,blank=False)
    Email = models.CharField(max_length=100,null=False,blank=False)
    Password = models.CharField(max_length=100,null=False,blank=False)
    # ConfirmPassword = models.CharField(max_length=100,null=False,blank=False)
    
    def __str__(self) -> str:
        return self.username 
    
class RegisterForm(UserCreationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={"placeholder":"Username"}))
    email = forms.CharField(widget=forms.EmailInput(attrs={"placeholder":"Email"}))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={"placeholder":"Password"}))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={"placeholder":"Re-enter password"}))

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def clean(self) -> Dict[str, Any]:
        return super().clean()