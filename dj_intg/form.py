from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import  Progress
from django import forms

from django.contrib.auth import get_user_model 
from django.contrib.auth.forms import SetPasswordForm


class RegisterForm(UserCreationForm):
    email=forms.CharField(widget=forms.EmailInput(attrs={"placeholder": "Enter email-address", "class": "form-control"}))
    username=forms.CharField(widget=forms.TextInput(attrs={"placeholder": "Enter email-username", "class": "form-control"}))
    password1=forms.CharField(label="Password", widget=forms.PasswordInput(attrs={"placeholder": "Enter password", "class": "form-control"}))
    password2=forms.CharField(label="Confirm Password", widget=forms.PasswordInput(attrs={"placeholder": "Confirm password", "class": "form-control"}))
    
    class Meta:
        model = get_user_model()
        fields = ["email", "username", "password1", "password2"]

class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label="Enter your email", max_length=254)


class PasswordResetForm(SetPasswordForm):
    new_password1 = forms.CharField(label="New password", widget=forms.PasswordInput)
    new_password2 = forms.CharField(label="Confirm new password", widget=forms.PasswordInput)
     
class ProgressForm(forms.ModelForm):
    class Meta:
        model = Progress
        # fields = ['matiere', 'revision_start_date', 'exam_date', 'hours_predicted', 'days_predicted', 'hours_suivi', 'days_suivi']
        fields = ['user', 'exam_date', 'revision_start_date', 'matiere', 'niveau', 'jours_rev', 'days_predicted', 'hours_predicted', 'days_suivi', 'hours_suivi', 'progressvalue']
        
    def __init__(self, *args, **kwargs):
        super(ModelForm, self).__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs['class'] = 'form-control'    
