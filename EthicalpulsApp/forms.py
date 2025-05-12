from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import *
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from .validators import validate_ip, validate_mac, validate_url
from django.core.validators import RegexValidator



class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password1', 'password2', 'role')

        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'id': 'username',
                'placeholder': "Nom d'utilisateur",
                'required': True,
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'id': 'email',
                'placeholder': 'exemple@domaine.com',
                'required': True,
            }),
            'role': forms.Select(attrs={
                'class': 'form-select',
                'id': 'role',
                'required': True,
            }),
        }

    def __init__(self, *args, **kwargs):
        super(CustomUserCreationForm, self).__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'id': 'password',
            'placeholder': 'Mot de passe',
            'required': True
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirmez le mot de passe',
            'required': True
        })
        
class EmailLoginForm(forms.Form):
    email = forms.EmailField(
        label="Adresse email",
        widget=forms.EmailInput(attrs={'placeholder': 'Adresse email', 'class': 'form-control'})
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={'placeholder': 'Mot de passe', 'class': 'form-control'})
    )

class OTPVerificationForm(forms.Form):
    otp_code = forms.CharField(
        label='Code OTP',
        max_length=6,  # Le code OTP standard est de 6 chiffres
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True,
    )

    def clean_otp_code(self):
        otp_code = self.cleaned_data.get('otp_code')
        
        # Vérification ici pour s'assurer que le code OTP est numérique
        if not otp_code.isdigit():
            raise ValidationError(_('Le code OTP doit être composé de chiffres.'))

        # Vérification de la longueur du code OTP (6 chiffres dans cet exemple)
        if len(otp_code) != 6:
            raise ValidationError(_('Le code OTP doit comporter exactement 6 chiffres.'))

        return otp_code


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ['name', 'description', 'project_type', 'domain', 'ip_address', 'url', 'scope']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom du projet'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Description du projet'}),
            'project_type': forms.Select(attrs={'class': 'form-control'}),
            'domain': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom de domaine'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Adresse IP'}),
            'url': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'URL du projet'}),
            'scope': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Portée du projet'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Vous pouvez aussi ajouter des styles conditionnels ou personnalisés ici si nécessaire.
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = field.widget.attrs.get('class', '') + ' custom-class'

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


validate_url = RegexValidator(
    regex=r'^(https?://)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*/?$',
    message='Entrez une URL valide.'
)
from django import forms
from .models import Scan
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

class ScanForm(forms.ModelForm):
    class Meta:
        model = Scan
        fields = ['name', 'project', 'tool']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom du scan'}),
            'project': forms.Select(attrs={'class': 'form-select'}),
            'tool': forms.Select(attrs={'class': 'form-select'}),
        }