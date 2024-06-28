from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import  Progress
from django import forms
from django.contrib.auth.forms import PasswordChangeForm

from django.contrib.auth import get_user_model 
from django.contrib.auth.forms import SetPasswordForm
from django import forms
from django.contrib.auth.forms import UserChangeForm, PasswordChangeForm
from .models import CustomUser, Profile
from django.core.exceptions import ValidationError
import re


class RegisterForm(UserCreationForm):
    email=forms.CharField(widget=forms.EmailInput(attrs={"placeholder": "Enter email-address", "class": "form-control"}))
    username=forms.CharField(widget=forms.TextInput(attrs={"placeholder": "Enter username", "class": "form-control"}))
    password1=forms.CharField(label="Password", widget=forms.PasswordInput(attrs={"placeholder": "Enter password", "class": "form-control"}))
    password2=forms.CharField(label="Confirm Password", widget=forms.PasswordInput(attrs={"placeholder": "Confirm password", "class": "form-control"}))
    
    class Meta:
        model = get_user_model()
        fields = ["email", "username", "password1", "password2"]

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not re.match("^[a-zA-Z0-9]*$", username):
            raise ValidationError("Username must contain only letters and numbers.")
        if len(username) < 5 or len(username) > 20:
            raise ValidationError("Username must be between 5 and 20 characters long.")
        if get_user_model().objects.filter(username=username).exists():
            raise ValidationError("Username already exists.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if get_user_model().objects.filter(email=email).exists():
            raise ValidationError("Email already exists.")
        return email

class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label="Enter your email", max_length=254)


class PasswordResetForm(SetPasswordForm):
    new_password1 = forms.CharField(label="New password", widget=forms.PasswordInput)
    new_password2 = forms.CharField(label="Confirm new password", widget=forms.PasswordInput)
    
class UpdateProfileForm(forms.ModelForm):
    avatar = forms.ImageField(required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email']

    def __init__(self, *args, **kwargs):
        super(UpdateProfileForm, self).__init__(*args, **kwargs)
        if not self.instance.is_staff:
            profile, created = Profile.objects.get_or_create(user=self.instance)
            self.fields['avatar'].initial = profile.avatar

    def save(self, commit=True):
        user = super(UpdateProfileForm, self).save(commit=False)
        if not user.is_staff:
            profile, created = Profile.objects.get_or_create(user=user)
            profile.avatar = self.cleaned_data.get('avatar', profile.avatar)
            if commit:
                user.save()
                profile.save()
        return user
    
    
class AvatarUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['avatar']
        
class ProgressForm(forms.ModelForm):
    class Meta:
        model = Progress
        # fields = ['matiere', 'revision_start_date', 'exam_date', 'hours_predicted', 'days_predicted', 'hours_suivi', 'days_suivi']
        fields = ['user', 'exam_date', 'revision_start_date', 'matiere', 'niveau', 'jours_rev', 'days_predicted', 'hours_predicted', 'days_suivi', 'hours_suivi', 'progressvalue']
        
    def __init__(self, *args, **kwargs):
        super(ModelForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'    
