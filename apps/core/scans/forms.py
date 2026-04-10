"""Forms for the scans app."""

import re
from django import forms

SCHEDULE_TYPE_CHOICES = [
    ("now", "Run now"),
    ("once", "Schedule once"),
    ("recurring", "Recurring"),
]

RECURRENCE_CHOICES = [
    ("daily", "Daily"),
    ("weekly", "Weekly"),
]

INPUT_CLASS = "w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"

# RFC 1035 / RFC 1123 domain pattern — labels separated by dots, no leading/trailing hyphens
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class StartScanForm(forms.Form):
    domain = forms.CharField(
        max_length=253,
        widget=forms.TextInput(attrs={
            "placeholder": "e.g. example.com",
            "class": INPUT_CLASS,
        }),
    )
    schedule_type = forms.ChoiceField(
        choices=SCHEDULE_TYPE_CHOICES,
        initial="now",
        widget=forms.RadioSelect(attrs={"class": "schedule-radio"}),
    )
    scheduled_at = forms.DateTimeField(
        required=False,
        input_formats=["%Y-%m-%dT%H:%M"],
        widget=forms.DateTimeInput(
            attrs={"type": "datetime-local", "class": INPUT_CLASS},
            format="%Y-%m-%dT%H:%M",
        ),
    )
    recurrence = forms.ChoiceField(
        choices=RECURRENCE_CHOICES,
        required=False,
        widget=forms.Select(attrs={"class": INPUT_CLASS}),
    )
    recurrence_time = forms.TimeField(
        required=False,
        input_formats=["%H:%M"],
        widget=forms.TimeInput(
            attrs={"type": "time", "class": INPUT_CLASS},
            format="%H:%M",
        ),
    )

    def clean_domain(self):
        domain = self.cleaned_data["domain"].strip().lower()
        if not _DOMAIN_RE.match(domain):
            raise forms.ValidationError(
                "Enter a valid domain name (e.g. example.com). "
                "No schemes, ports, or paths."
            )
        return domain

    def clean(self):
        cleaned = super().clean()
        schedule_type = cleaned.get("schedule_type")
        if schedule_type == "once" and not cleaned.get("scheduled_at"):
            self.add_error("scheduled_at", "Please select a date and time.")
        if schedule_type == "recurring":
            if not cleaned.get("recurrence"):
                self.add_error("recurrence", "Please select daily or weekly.")
            if not cleaned.get("recurrence_time"):
                self.add_error("recurrence_time", "Please select a time for the recurring scan.")
        return cleaned
