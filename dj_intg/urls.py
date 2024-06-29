from django.urls import path
from .  import views
from .views import *




urlpatterns=[
    path('',views.dashbord,name='dashbord'),
    path('indexS/', views.dashboard, name='indexS'),
    path('profile/', views.profile, name='profile'),
    
    path("register", views.register, name="register"),
    path("verify-email/<slug:username>", views.verify_email, name="verify-email"),
    path("resend-otp", views.resend_otp, name="resend-otp"),
    path('login', views.signin, name='login'),
    path('password-reset/', password_reset_request, name='password_reset_request'),
    path('reset-password/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('logout/', logout_view, name='logout'),

    #Update profile urls
    path('update_profile_info/', update_profile_info, name='update_profile_info'),
    path('change_password/', change_password, name='change_password'),
    path('update_avatar/', update_avatar, name='update_avatar'),


    # pylint: disable=invalid-name

    path('calendar/', views.calendar, name='calendar'),

    path('progress/', views.progress, name='progress'),
    path('get-chart-data/', views.get_chart_data, name='get-chart-data'),
    path('linechart', views.linechart, name='linechart'),
    
    path('examSchedule/', views.examSchedule, name='examSchedule'),
 
    #path('register/', views.register, name='register'),

    path('formProgress/', views.formProgress, name='formProgress'),
    path('delete/<int:id>/', deletedata, name='deletedata'),
    path('detailmatiere/', views.detailmatiere, name='detailmatiere'),
    path('detailmatiere/<int:progress_id>/', views.detailmatiere, name='detailmatiere'),
    path('updateprogress/<int:progress_id>/', views.updateprogress, name='updateprogress'),



]
