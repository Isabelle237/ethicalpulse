from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import *
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from .validators import validate_ip, validate_url
from django.core.validators import RegexValidator


# Formulaire de création d'utilisateur personnalisé
class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2', 'role')

        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control custom-input',
                'placeholder': "Nom d'utilisateur",
                'required': True,
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control custom-input',
                'placeholder': 'exemple@domaine.com',
                'required': True,
            }),
            'role': forms.Select(attrs={
                'class': 'form-select custom-select',
                'required': True,
            }),
        }

    def __init__(self, *args, **kwargs):
        super(CustomUserCreationForm, self).__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control custom-input',
            'placeholder': 'Mot de passe',
            'required': True
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control custom-input',
            'placeholder': 'Confirmez le mot de passe',
            'required': True
        })


# Formulaire de connexion par email
class EmailLoginForm(forms.Form):
    email = forms.EmailField(
        label="Adresse email",
        widget=forms.EmailInput(attrs={'placeholder': 'Adresse email', 'class': 'form-control custom-input'})
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={'placeholder': 'Mot de passe', 'class': 'form-control custom-input'})
    )


# Formulaire de vérification OTP
class OTPVerificationForm(forms.Form):
    otp_code = forms.CharField(
        label='Code OTP',
        max_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Entrez le code OTP'}),
        required=True,
    )

    def clean_otp_code(self):
        otp_code = self.cleaned_data.get('otp_code')
        if not otp_code.isdigit():
            raise ValidationError(_('Le code OTP doit être composé de chiffres.'))
        if len(otp_code) != 6:
            raise ValidationError(_('Le code OTP doit comporter exactement 6 chiffres.'))
        return otp_code


# Formulaire de projet
class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'description', 'project_type', 'domain', 'ip_address', 'url']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Nom du projet'}),
            'description': forms.Textarea(attrs={'class': 'form-control custom-textarea', 'placeholder': 'Description'}),
            'project_type': forms.Select(attrs={'class': 'form-select custom-select'}),
            'domain': forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Nom de domaine'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Adresse IP'}),
            'url': forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'URL du projet'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] += ' custom-class'

    def clean_ip_address(self):
        ip = self.cleaned_data.get('ip_address')
        if ip:
            validate_ip(ip)
        return ip

    def clean_url(self):
        url = self.cleaned_data.get('url')
        if url:
            validate_url(url)
        return url


# Formulaire de scan planifié


from django import forms
from .models import ScheduledScan
from django.core.exceptions import ValidationError
from django.utils import timezone

class ScheduledScanForm(forms.ModelForm):
    class Meta:
        model = ScheduledScan
        fields = ['name', 'description', 'tool', 'target', 'frequency', 
                 'next_run_time', 'email_notification']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'next_run_time': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'tool': forms.Select(attrs={'class': 'form-select'}),
            'target': forms.Select(attrs={'class': 'form-select'}),
            'frequency': forms.Select(attrs={'class': 'form-select'}),
        }

    def clean_next_run_time(self):
        next_run_time = self.cleaned_data.get('next_run_time')
        if next_run_time and next_run_time < timezone.now():
            raise ValidationError("La date d'exécution doit être dans le futur")
        return next_run_time

    def __init__(self, *args, **kwargs):
        super(ScheduledScanForm, self).__init__(*args, **kwargs)

        # Récupérer les choix TOOL_CHOICES depuis le modèle
        self.fields['tool'].choices = ScheduledScan._meta.get_field('tool').choices
        self.fields['tool'].widget.attrs.update({'class': 'form-select'})

        self.fields['target'].empty_label = "Sélectionnez une cible"

from django import forms
from .models import SystemLog

class LogExportForm(forms.Form):
    FORMAT_CHOICES = [
        ('csv', 'CSV'),
        ('json', 'JSON'),
        ('xml', 'XML'),
    ]
    
    format = forms.ChoiceField(choices=FORMAT_CHOICES)
    date_from = forms.DateField(required=False)
    date_to = forms.DateField(required=False)
    include_auth = forms.BooleanField(required=False, initial=True)
    include_scan = forms.BooleanField(required=False, initial=True)
    include_vuln = forms.BooleanField(required=False, initial=True)
    include_system = forms.BooleanField(required=False, initial=True)
    
    def clean(self):
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')
        
        if date_from and date_to and date_from > date_to:
            raise forms.ValidationError("La date de début doit être antérieure à la date de fin")
            
        return cleaned_data
# Formulaire de scan
class ScanForm(forms.ModelForm):
    class Meta:
        model = Scan
        fields = ['name', 'project', 'tool']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control custom-input', 'placeholder': 'Nom du scan'}),
            'project': forms.Select(attrs={'class': 'form-select custom-select'}),
            'tool': forms.Select(attrs={'class': 'form-select custom-select'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] += ' custom-class'