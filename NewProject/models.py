from django.db import models

class AddUsers(models.Model):
    username = models.CharField(max_length=100, null=False,blank=False)
    password = models.CharField(max_length=100, null=False,blank=False)
    email = models.CharField(max_length=100, null=False,blank=False)
    description = models

