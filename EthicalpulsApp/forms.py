from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser,Project
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

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
        fields = ['name', 'description', 'project_type', 'domain', 'ip_address', 'url', 'scope', 'mac_address']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'project_type': forms.Select(attrs={'class': 'form-select'}),
            'domain': forms.TextInput(attrs={'class': 'form-control'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control'}),
            'url': forms.URLInput(attrs={'class': 'form-control'}),
            'scope': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'mac_address': forms.TextInput(attrs={'class': 'form-control'}),
        }
