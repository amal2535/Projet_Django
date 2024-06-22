from django.db import models
from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.conf import settings
import secrets
from django.contrib.auth.models import AbstractUser, Group, Permission

class Account(models.Model):
    # ROLE_CHOICES = (
    # ('Admin', 'Admin'),
    # ('Etudiant', 'Etudiant') 
    # )
    # role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    user_image=models.ImageField(null=True,blank=True)
    user =models.OneToOneField(User,on_delete=models.CASCADE,null=True)

    def __str__(self):
        return str(self.user.username)
    
# Create your models here.
# class UserEsprit(models.Model):
#     username = models.CharField(max_length=100)
#     email = models.EmailField()
#     password = models.CharField(max_length=100)
#     image = models.ImageField(upload_to='images/', null=True, blank=True)  # Champ image facultatif
    
#     # Choix possibles pour le rôle de l'utilisateur
#     ROLE_CHOICES = (
#     ('admin', 'Admin'),
#     ('etudiant', 'Etudiant')
# )
#     role = models.CharField(max_length=10, choices=ROLE_CHOICES)
# def __str__(self):
#         return self.username


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',  # Unique related_name to avoid conflicts
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_set',  # Unique related_name to avoid conflicts
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def __str__(self):
        return self.email
class OtpToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="otps")
    otp_code = models.CharField(max_length=6, default=secrets.token_hex(3))
    tp_created_at = models.DateTimeField(auto_now_add=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)
    
    
    def __str__(self):
        return self.user.username

    
class Progress(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    exam_date = models.DateField()
    revision_start_date = models.DateField()
    matiere = models.CharField(max_length=100)
    niveau = models.CharField(max_length=100)
    jours_rev = models.IntegerField()
    days_predicted = models.IntegerField()  # prédiction du modèle
    hours_predicted = models.IntegerField()  # prédiction du modèle
    days_suivi = models.IntegerField()
    hours_suivi = models.IntegerField()
    progressvalue = models.FloatField(default=0) 
    def __str__(self):
        return f"{self.user.username} - {self.matiere} - Exam Date: {self.exam_date}"
    

