from django import forms
from .models import Domain


class DomainForm(forms.ModelForm):
    class Meta:
        model = Domain
        fields = ["name", "is_primary"]
        widgets = {
            "name": forms.TextInput(attrs={
                "placeholder": "e.g. example.com",
                "class": "w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500",
            }),
            "is_primary": forms.CheckboxInput(attrs={
                "class": "h-4 w-4 text-indigo-600 border-gray-300 rounded",
            }),
        }
