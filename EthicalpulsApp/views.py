from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model,logout,login


import pyotp

from EthicalpulsApp.models import CustomUser
from .forms import CustomUserCreationForm, EmailLoginForm, OTPVerificationForm

# =================== Pages Générales ===================

def index(request):
    return render(request, 'dashboard/index.html')

def dashboard(request):
    return render(request, 'admin/dashboard.html')

# =================== Utilisateurs ===================

@csrf_protect
def create_user_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.save()

            html_message = render_to_string('emails/account_confirmation.html', {
                'username': user.username,
            })
            plain_message = strip_tags(html_message)

            send_mail(
                subject="Confirmation de création de compte",
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )

            messages.success(request, "L'utilisateur a été créé avec succès.")
            return redirect('users')
        else:
            messages.error(request, "Une erreur est survenue lors de la création de l'utilisateur.")
    else:
        form = CustomUserCreationForm()

    users_list = CustomUser.objects.all()
    return render(request, 'admin/users.html', {
        'form': form,
        'users_list': users_list
    })

@csrf_protect
def edit_user_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, "L'utilisateur a été mis à jour.")
            return redirect('users')
        else:
            messages.error(request, "Erreur lors de la mise à jour de l'utilisateur.")
    else:
        form = CustomUserCreationForm(instance=user)

    return render(request, 'admin/edit_user_modal.html', {'form': form, 'user': user})

@require_POST
def delete_user_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.delete()
    messages.success(request, "L'utilisateur a été supprimé.")
    return redirect('users')

@require_POST
def delete_multiple_users_view(request):
    ids = request.POST.getlist('user_ids[]')
    if ids:
        CustomUser.objects.filter(id__in=ids).delete()
        messages.success(request, f"{len(ids)} utilisateur(s) supprimé(s).")
    else:
        messages.warning(request, "Aucun utilisateur sélectionné.")
    return redirect('users')

# =================== Authentification ===================


@csrf_protect
def email_login(request):
    if request.method == 'POST':
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                otp = pyotp.TOTP(user.otp_secret).now()
                send_otp_email(user, otp)
                request.session['pre_otp_user_id'] = user.id
                return redirect('verify_otp')
            messages.error(request, "Identifiants incorrects.")
    else:
        form = EmailLoginForm()
    return render(request, 'registration/login.html', {'form': form})

@csrf_protect
def otp_verification(request):
    user_id = request.session.get('pre_otp_user_id')
    if not user_id:
        return redirect('login')
    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp_code):
                login(request, user)
                del request.session['pre_otp_user_id']
                messages.success(request, "Connecté avec succès.")
                return redirect('dashboard')
            messages.error(request, "Code OTP invalide.")
    else:
        form = OTPVerificationForm()
    return render(request, 'registration/otp_verification.html', {'form': form, 'user': user})

def send_otp_email(user, otp_code):
    html_message = render_to_string('emails/otp_confirmation.html', {
        'user': user,
        'otp_code': otp_code,
        'current_year': timezone.now().year,
    })
    plain_message = strip_tags(html_message)
    send_mail(
        subject="Votre code OTP - EthicalPulseShield",
        message=plain_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        html_message=html_message,
        fail_silently=False,
    )
def send_otp_email(user, otp_code):
    subject = "Vérification OTP - EthicalPulseShield"
    current_year = timezone.now().year

    html_message = render_to_string('emails/otp_confirmation.html', {
        'user': user,
        'otp_code': otp_code,
        'current_year': current_year
    })
    plain_message = strip_tags(html_message)

    send_mail(
        subject,
        plain_message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        html_message=html_message,
        fail_silently=False,
    )


def logout_view(request):
    logout(request)
    request.session.flush()  # Efface toutes les données de session (dont otp_validated)
    messages.success(request, "Vous avez été déconnecté avec succès.")
    return redirect('login')
# =================== Autres vues ===================

def projects(request):
    return render(request, 'admin/projects.html')

def project_detail(request, project_id):
    return render(request, 'admin/project_detail.html')

def projects_create(request):
    return redirect('projects')

def projects_edit(request, project_id):
    return redirect('projects')

def projects_delete(request, project_id):
    return redirect('projects')

def scans(request):
    return render(request, 'scans.html')

def scans_create(request):
    return redirect('scans')

def scans_edit(request, scan_id):
    return redirect('scans')

def scans_delete(request, scan_id):
    return redirect('scans')

def scans_start(request, scan_id):
    return redirect('scans')

def scans_cancel(request, scan_id):
    return redirect('scans')

def vulnerabilities(request):
    return render(request, 'vulnerabilities.html')

def vulnerabilities_admin(request):
    return render(request, 'admin/vulnerabilities.html')

def vulnerabilities_create(request):
    return redirect('vulnerabilities')

def vulnerabilities_edit(request, vuln_id):
    return redirect('vulnerabilities')

def vulnerabilities_delete(request, vuln_id):
    return redirect('vulnerabilities')

def tools_admin(request):
    return render(request, 'admin/tools.html')

def tools(request):
    return render(request, 'tools/index.html')

def tools_create(request):
    return redirect('tools')

def tools_edit(request, tool_id):
    return redirect('tools')

def tools_delete(request, tool_id):
    return redirect('tools')

def tools_run(request, tool_id):
    return redirect('tools')

def remediations(request):
    return render(request, 'remediation.html')

def remediations_admin(request):
    return render(request, 'admin/remediation.html')

def remediation_detail(request, remediation_id):
    return render(request, 'admin/remediation_detail.html')

def remediations_create(request):
    return redirect('remediations')

def remediations_edit(request, remediation_id):
    return redirect('remediations')

def remediations_delete(request, remediation_id):
    return redirect('remediations')

def remediations_execute(request, remediation_id):
    return redirect('remediations')

def settings_admin(request):
    return render(request, 'admin/settings.html')

def settings_users(request):
    return render(request, 'settings.html')

def logs(request):
    return render(request, 'admin/logs.html')

def errorPage(request):
    return render(request, 'dashboard/404.html')

def history(request):
    return render(request, 'history.html')

def report(request):
    return render(request, 'reports.html')

def training(request):
    return render(request, 'training.html')

def analytics(request):
    return render(request, 'analytics.html')

def scans_admin(request):
    return render(request, 'admin/scans.html')
