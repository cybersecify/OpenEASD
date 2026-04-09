"""Forms for the scans app."""

from django import forms


SCAN_TYPE_CHOICES = [
    ("full", "Full Scan"),
    ("incremental", "Incremental Scan"),
]


class StartScanForm(forms.Form):
    domain = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            "placeholder": "e.g. example.com",
            "class": "w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500",
        }),
    )
    scan_type = forms.ChoiceField(
        choices=SCAN_TYPE_CHOICES,
        initial="full",
        widget=forms.Select(attrs={
            "class": "w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500",
        }),
    )
