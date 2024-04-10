from django.db import models

# Create your models here.
class AddUser(models.Model):
    Username = models.CharField(max_length=100,null=False,blank=False)
    Email = models.CharField(max_length=100,null=False,blank=False)
    Password = models.CharField(max_length=100,null=False,blank=False)
    # ConfirmPassword = models.CharField(max_length=100,null=False,blank=False)
    

    def __str__(self) -> str:
        return self.username 