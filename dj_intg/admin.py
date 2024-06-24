from django.contrib import admin
from .models import *
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import Profile 
from .models import Progress
# from .models import UserEsprit
# Register your models here.
# from django.contrib.auth.models import User

# admin.site.register(User)

"""
class AccountInline(admin.StackedInline):
    model = Account
    can_delete=False
    verbose_name_plural= 'Accounts'

class CustomizedUserAdmin(UserAdmin):
    inlines =(AccountInline, )

admin.site.unregister(User)
admin.site.register(User,CustomizedUserAdmin)
admin.site.register(Account)
admin.site.register(Progress)
    
    """

from django.contrib import admin
from .models import User, OtpToken
from django.contrib.auth.admin import UserAdmin
# Register your models here.

class CustomUserAdmin(UserAdmin):
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2')}
         ),
    )


class OtpTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_code")


admin.site.register(OtpToken, OtpTokenAdmin)
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Progress)
admin.site.register(Profile)
