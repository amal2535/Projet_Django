from django.db import models
from django.contrib.auth.models import User
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.conf import settings
import secrets
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set', 
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions_set',  
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def __str__(self):
        return self.email

class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    avatar = models.ImageField(upload_to='static/images', default='Front1/images/user.png')

    def __str__(self):
        return self.user.email

@receiver(post_save, sender=CustomUser)
def create_or_update_profile(sender, instance, created, **kwargs):
    if not instance.is_staff:
        if created:
            Profile.objects.create(user=instance)
        else:
            try:
                instance.profile.save()
            except Profile.DoesNotExist:
                Profile.objects.create(user=instance)

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
    days_predicted = models.IntegerField()
    hours_predicted = models.IntegerField()  
    days_suivi = models.IntegerField()
    hours_suivi = models.IntegerField()
    progressvalue = models.FloatField(default=0) 
    demi_journee = models.BooleanField(default=False)
    predh = models.CharField(max_length=50, default='')


    def __str__(self):
        return f"{self.user.username} - {self.matiere} - Exam Date: {self.exam_date}"
