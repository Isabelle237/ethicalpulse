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