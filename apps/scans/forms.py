"""Forms for the scans app."""

from django import forms


SCAN_TYPE_CHOICES = [
    ("full", "Full Scan"),
    ("incremental", "Incremental Scan"),
]

INPUT_CLASS = "w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"


class StartScanForm(forms.Form):
    domain = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            "placeholder": "e.g. example.com",
            "class": INPUT_CLASS,
        }),
    )
    scan_type = forms.ChoiceField(
        choices=SCAN_TYPE_CHOICES,
        initial="full",
        widget=forms.Select(attrs={"class": INPUT_CLASS}),
    )
    workflow = forms.IntegerField(
        required=False,
        widget=forms.Select(attrs={"class": INPUT_CLASS}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from apps.workflow.models import Workflow
        choices = [("", "— Default pipeline (all tools) —")]
        choices += [(w.pk, w.name) for w in Workflow.objects.all()]
        self.fields["workflow"].widget.choices = choices
