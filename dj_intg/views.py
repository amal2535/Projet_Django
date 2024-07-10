
import datetime
from django.shortcuts import get_object_or_404, render,redirect
import pandas as pd
from dj_intg.form import  ProgressForm
from django.contrib import messages
from django.contrib.auth.models import User
from .models import Profile,Progress
from django.shortcuts import HttpResponseRedirect
from joblib import load
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils.encoding import  force_str
from django.contrib.auth import get_user_model
User = get_user_model()
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
force_str(User.pk)
import datetime as dt
from .form import AvatarUpdateForm, PasswordResetForm, PasswordResetRequestForm, RegisterForm
from .models import OtpToken
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from datetime import datetime
import jwt
import datetime
from django.conf import settings
from rest_framework.decorators import api_view
from .form import RegisterForm
from .models import OtpToken
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.decorators import login_required
from .form import UpdateProfileForm
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from datetime import date
from django.utils.dateparse import parse_datetime
from datetime import datetime as dt, timedelta
import pandas as pd
from joblib import load


def get_color(progress_value):
    if progress_value < 25:
        return '#FF3737'  # Red
    elif progress_value < 50:
        return '#77DD77'  # green
    elif progress_value < 75:
        return '#800080'  # Purple
    else:
        return '#FFBF00'  # yellow


@login_required
def dashboard1(request):
    progresses = Progress.objects.filter(user=request.user)
    today = date.today()

    exams_taken = [progress.matiere for progress in progresses if progress.exam_date < today]
    exams_in_progress = [
        {
            'name': progress.matiere,
            'days_left': (progress.exam_date - today).days,
        }
        for progress in progresses if progress.exam_date >= today
    ]

    exams_passed_count = len(exams_taken)
    exams_remaining_count = len(exams_in_progress)

    subjects = [
        {'name': progress.matiere, 'progress': progress.progressvalue, 'color': get_color(progress.progressvalue)}
        for progress in progresses if progress.exam_date >= today
    ]

    context = {
        'user': request.user,
        'subjects': subjects,
        'exams_taken': exams_taken,
        'exams_in_progress': exams_in_progress,
        'exams_passed_count': exams_passed_count,
        'exams_remaining_count': exams_remaining_count,
    }

    return render(request, 'indexS.html', context)


def dashboard(request, *args, **kwargs):
    return render(request, 'index.html')

def indexS(request):
    """Renders the indexS page."""
    return render(request, 'indexS.html')

def profile(request):
    """Renders the profile page."""
    return render(request, 'profile.html')


@api_view(['POST', 'GET'])
def register(request):
    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Account created successfully! An OTP was sent to your Email")
            return redirect("verify-email", username=user.username)
    context = {"form": form}
    return render(request, "register.html", context)

@api_view(['POST', 'GET'])
def verify_email(request, username):
    if request.method == 'POST':
        user = get_object_or_404(get_user_model(), username=username)
        user_otp = OtpToken.objects.filter(user=user).last()

        if user_otp and user_otp.otp_code == request.data.get('otp_code'):
            if user_otp.otp_expires_at > timezone.now():
                user.is_active = True
                user.save()
                # Generate JWT
                payload = {
                    'user_id': user.id,
                    'username': user.username,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
                }
                token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')

                login(request, user)
                return redirect("indexS")

            else:
                messages.warning(request, "The OTP has expired, get a new OTP!")
                return redirect("verify-email", username=username)
        else:
            messages.warning(request, "Invalid OTP entered, enter a valid OTP!")
            return redirect("verify-email", username=username)

    return render(request, "verify_token.html", {})


def resend_otp(request):
    if request.method == 'POST':
        user_email = request.POST.get("otp_email")
        
        users = get_user_model().objects.filter(email=user_email)
        if users.exists():
            for user in users:
                otp = OtpToken.objects.create(user=user, otp_expires_at=timezone.now() + timezone.timedelta(minutes=5))
                
                subject = "Email Verification"
                message = f"""
                Hi {user.username}, here is your OTP {otp.otp_code} 
                it expires in 5 minutes. Use the URL below to redirect back to the website:
                http://127.0.0.1:8000/verify-email/{user.username}
                """
                receiver = [user.email]
            
                # Send email
                send_mail(
                    subject,
                    message,
                    None,
                    receiver,
                    fail_silently=False,
                )
            
            messages.success(request, "A new OTP has been sent to your email address")
            return redirect("verify-email", username=users.first().username)

        else:
            messages.warning(request, "This email doesn't exist in the database")
            return redirect("resend-otp")
        
    context = {}
    return render(request, "resend_otp.html", context)

@api_view(['POST', 'GET'])
def signin(request):
    if request.method == 'POST':
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("indexS")
        else:
            messages.warning(request, "Invalid credentials")
            return render(request, 'login.html')

    return render(request, 'login.html')


# Logout function
@api_view(['POST', 'GET'])
def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out successfully.")
    return redirect("login")

def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = get_user_model().objects.filter(email=email).first()
            if user:
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_link = request.build_absolute_uri(f'/reset-password/{uid}/{token}/')
                message = render_to_string('password_reset_email.html', {
                    'user': user,
                    'reset_link': reset_link,
                })

                email_subject = 'Password Reset Request'
                email_body = message
                email = EmailMultiAlternatives(subject=email_subject, body=email_body, to=[email])
                email.attach_alternative(email_body, "text/html")
                email.send()

                messages.success(request, "A password reset link has been sent to your email address.")
                return redirect('login')
            else:
                messages.warning(request, "No user is associated with this email address.")
                return redirect('password_reset_request')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'password_reset_request.html', {'form': form})

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = PasswordResetForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, "Your password has been reset successfully.")
                return redirect('login')
        else:
            form = PasswordResetForm(user)
    else:
        messages.warning(request, "The password reset link is invalid.")
        return redirect('password_reset_request')

    return render(request, 'password_reset_confirm.html', {'form': form})



@login_required
def update_profile_info(request):
    user = request.user
    if not user.is_staff:
        Profile.objects.get_or_create(user=user) 
    
    if request.method == 'POST':
        form = UpdateProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            return redirect('profile')  
    else:
        form = UpdateProfileForm(instance=user)
    
    context = {'form': form}
    if not user.is_staff:
        context['profile'] = user.profile
    
    return render(request, 'profile.html', context)

@login_required
def update_avatar(request):
    user_profile, created = Profile.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        form = AvatarUpdateForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            form.save()
            return redirect('profile')
    else:
        form = AvatarUpdateForm(instance=user_profile)
    return render(request, 'profile.html', {'form': form})

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user) 
            messages.success(request, 'Your password was successfully updated!')
            return redirect('profile')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'profile.html', {'password_change_form': form})


# Define the matiere_names dictionary with all options
matiere_names = {
    '0': "Administration & sécurité des SE (Unix)",
    '1': "Algorithmique 1",
    '2': "Algorithmique 2",
    '3': "Analyse et Décisions Financières",
    '4': "Analyse numérique",
    '5': "Architecture des microcontrôleurs",
    '6': "Bases de Données",
    '7': "CCNA",
    '8': "Calcul Scientifique",
    '9': "Communication, Culture et Citoyenneté A1",
    '10': "Communication, Culture et Citoyenneté A2",
    '11': "Communication, Culture et Citoyenneté A3",
    '12': "Communication, Culture et Citoyenneté F1",
    '13': "Communication, Culture et Citoyenneté F2",
    '14': "Communication, Culture et Citoyenneté F3",
    '15': "Conception par Objet et Programmation Java",
    '16': "Environnement de l'entreprise",
    '17': "Fondements des réseaux",
    '18': "Génie logiciel & atelier GL",
    '19': "IP essentials",
    '20': "IPNet routing",
    '21': "Infographie et montage vidéo",
    '22': "Langage de Modélisation (UML)",
    '23': "Mathématiques de base 1",
    '24': "Mathématiques de base 2",
    '25': "Mathématiques de base 3",
    '26': "Mathématiques de base 4",
    '27': "Programmation Orientée Objet (C++)",
    '28': "Programmation Procédurale 1",
    '29': "Programmation Procédurale 2",
    '30': "Programmation des terminaux mobiles",
    '31': "Réseaux de communication",
    '32': "Switched Networks",
    '33': "Sys. De Gestion de Bases de Données",
    '34': "Systèmes et Réseaux",
    '35': "Systèmes et Scripting",
    '36': "Techniques d'estimation pour l'ingénieur",
    '37': "Technologies Web 2.0",
    '38': "Théorie des langages(TLA)"
}


@login_required
def calendar_view(request):
    context = {
        'prediction_made': request.GET.get('prediction_made', 'False') == 'True',
        'predh': request.GET.get('predh', ''),
        'matiere': request.GET.get('matiere', ''),
        'start_date': request.GET.get('start_date', ''),
        'end_date': request.GET.get('end_date', ''),
        'date_exam': request.GET.get('date_exam', ''),
        'demi_journee': request.GET.get('demi_journee', 'False') == 'True',
    }
    return render(request, 'calendar.html', context)

@login_required
def examSchedule(request):
    predh = None
    prediction_made = False
    start_date = None
    end_date = None
    data = {
        'Matière': 0, 'Coefficient': 0, 'Nombre_de_jours_de_revision_total': 0, 'Niveau_Etudiant': 0
    }
    model_ann = load('data/gradient_boosting_model.joblib')

    if request.method == "POST":
        niveau = request.POST.get('niveau')
        matiere = request.POST.get('matiere')
        matiereOut = matiere
        coefficient = request.POST.get('coefficient')
        debut_revision_str = request.POST.get('debut_revision')
        date_examen_str = request.POST.get('date_examen')

        def clean_input(value):
            return ''.join(filter(str.isdigit, value))

        niveau = clean_input(niveau)
        matiere = clean_input(matiere)
        coefficient = clean_input(coefficient)
        if niveau:
            data['Niveau_Etudiant'] = int(niveau)
        if matiere:
            data['Matière'] = int(matiere)
        if coefficient:
            data['Coefficient'] = int(coefficient)

        if debut_revision_str and date_examen_str:
            debut_revision = parse_datetime(debut_revision_str)
            date_examen = parse_datetime(date_examen_str)
            difference_jours = (date_examen - debut_revision).days

            if difference_jours < 5:
                data['Nombre_de_jours_de_revision_total'] = 1
            elif 5 <= difference_jours <= 10:
                data['Nombre_de_jours_de_revision_total'] = 0
            else:
                data['Nombre_de_jours_de_revision_total'] = 3

        df = pd.DataFrame([data])

        predh = model_ann.predict(df.values)
        predh = int(predh[0])

        jours = predh // 8
        heures_restantes = predh % 8
        if heures_restantes >= 4:
            jours += 1
            demi_journee = False
        else:
            demi_journee = True

        if demi_journee:
            if jours == 0:
                predh = "demi-journée"
            else:
                predh = f"{jours} jours et demi-journée"
        else:
            predh = f"{jours} jours"

        start_date = debut_revision.date()
        end_date = start_date + timedelta(days=jours)

        progress_instance = Progress(
            user=request.user,
            exam_date=date_examen,
            revision_start_date=debut_revision,
            matiere=matiereOut,
            niveau=niveau,
            days_predicted=jours,
            hours_predicted=heures_restantes,
            days_suivi=0,
            hours_suivi=0,
        )
        progress_instance.save()

        prediction_made = True
        return render(request, 'examSchedule.html', {
            'predh': predh,
            'prediction_made': prediction_made,
            'start_date': start_date,
            'end_date': end_date,
            'date_exam': date_examen_str,
            'matiere': matiereOut,
            'demi_journee': demi_journee 
        })
    
    return render(request, 'examSchedule.html')
@login_required
def formProgress(request):
    user_progress = Progress.objects.filter(user=request.user)
    
    context = {"DATA": user_progress}
    
    return render(request, 'formProgress.html', context)



def deletedata(request, id):
    progress = Progress.objects.get(id=id)
    progress.delete()
    return redirect('formProgress')


def detailmatiere(request, progress_id):
    progress = get_object_or_404(Progress, pk=progress_id)
    jours_rev = (progress.exam_date - progress.revision_start_date).days
    
    if request.method == 'POST':
        form = ProgressForm(request.POST, instance=progress)
        if form.is_valid():
            # Récupérer les valeurs actuelles de days_suivi et hours_suivi
            days_suivi_current = progress.days_suivi
            hours_suivi_current = progress.hours_suivi
            
            # Récupérer les nouvelles valeurs saisies par l'utilisateur
            days_suivi_new = form.cleaned_data['days_suivi']
            hours_suivi_new = form.cleaned_data['hours_suivi']
            
            # Ajouter les nouvelles valeurs aux valeurs actuelles
            progress.days_suivi = days_suivi_current + days_suivi_new
            progress.hours_suivi = hours_suivi_current + hours_suivi_new
            
            # Enregistrer les modifications dans la base de données
            progress.save()
            
            return HttpResponseRedirect('detailmatiere')  # Rediriger après enregistrement
    else:
        form = ProgressForm(instance=progress)
    
    context = {
        'matiere': progress.matiere,
        'niveau': progress.niveau,
        'exam_date': progress.exam_date,
        'revision_start_date': progress.revision_start_date,
        # 'days_predicted': progress.days_predicted,
        'hours_predicted': progress.hours_predicted,
        # 'days_suivi': progress.days_suivi,
        'hours_suivi': progress.hours_suivi,
        'jours_rev': jours_rev,
        'form': form,
    }
    
    return render(request, 'detailmatiere.html', context)


@login_required
def updateprogress(request, progress_id):
    user_progress = get_object_or_404(Progress, pk=progress_id)
    error_message = None
    
    if request.method == 'POST':
        try:
            tot_studying_hours = int(request.POST.get('tot_studying_hours'))
            # Calculate new values
            new_hours_suivi = user_progress.hours_suivi + tot_studying_hours
            predicted_time = user_progress.days_predicted * 8 + user_progress.hours_predicted
            print(predicted_time)
            # Validate input
            if new_hours_suivi > predicted_time:
                error_message = "Error: Studying hours exceed predicted hours."
            else:
                # Update user_progress
                user_progress.hours_suivi = new_hours_suivi
                user_progress.progressvalue = (user_progress.hours_suivi) / (predicted_time)
                user_progress.progressvalue = round(user_progress.progressvalue * 100)
                user_progress.save()
                return render(request, 'updateprogress.html', {'user_progress': user_progress})
        except ValueError:
            error_message = "Invalid input. Please enter numeric values."

    context = {
        'user_progress': user_progress,
        'error_message': error_message
    }
    return render(request, 'updateprogress.html', context)


# Définir la fonction pour déterminer le niveau de risque
def determiner_niveau_risque(matiere, predh):
    # Dictionnaire des moyennes par matière
    moyennes = {
       "Unix": 14.62,
        "Algo1": 11.21,
        "Algo2": 12.11,
        "ADF": 6.48,
        "Analys_num": 14.22,
        "Arch_Micro": 11.13,
        "BD": 8.60,
        "CCNA": 8.80,
        "Calcul_Sc": 9.58,
        "CCCA1": 4.34,
        "CCCA2": 3.33,
        "CCCA3": 1.88,
        "CCCF1": 3.23,
        "CCCF2": 3.03,
        "CCCF3": 2.78,
        "Java": 17.68,
        "Env_entreprise": 4.71,
        "Fond_RX": 11.22,
        "GL": 8.01,
        "IP_essentials": 6.87,
        "IPNet_routing": 10.08,
        "Multimedia": 4.45,
        "UML": 9.59,
        "MB1": 17.51,
        "MB2": 18.56,
        "MB3": 22.36,
        "MB4": 22.07,
        "POO_Cplus": 16.27,
        "ProgProc1": 13.53,
        "ProgProc2": 13.78,
        "Mobile": 11.33,
        "Rx_comm": 11.73,
        "Switched_Networks": 9.33,
        "SGBD": 10.33,
        "SysRX": 10.87,
        "Sys_Scripting": 8.76,
        "Proba": 15.29,
        "Tech_Web": 8.60,
        "TLA": 11.87,
        "Electronique": 9.84
    }

    # Vérifier si la matière existe dans le dictionnaire
    if matiere not in moyennes:
        return f"La matière '{matiere}' n'est pas présente dans les données."

    # Calcul des niveaux de risque
    moyenne = moyennes[matiere]
    niveau_moyen = moyenne
    niveau_faible = moyenne * 1.3
    niveau_fort = moyenne / 1.3
    niveau_tres_fort = moyenne / 1.6

    # Déterminer le niveau de risque
    if predh >= niveau_faible:
        return "Niv faible"
    elif predh >= niveau_moyen:
        return "Niv moyen"
    elif predh >= niveau_fort:
        return "Niv fort"
    elif predh >= niveau_tres_fort:
        return "Niv très fort"
    else:
        return "Hors catégorie"
