from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser

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
        label="Code de vérification",
        max_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': 'Entrez le code OTP',
            'class': 'form-control',
            'autocomplete': 'off',
        })
    )
