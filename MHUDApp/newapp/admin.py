from django.contrib import admin
from .models import *

# Register your models here.

class UserfromAdmin(admin.ModelAdmin):
    list_display = ['Username', 'Email', 'Password']

admin.site.register(AddUser, UserfromAdmin)