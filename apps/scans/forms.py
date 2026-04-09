"""Forms for the scans app."""

from django import forms

SCAN_TYPE_CHOICES = [
    ("full", "Full Scan"),
    ("incremental", "Incremental Scan"),
]

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


class StartScanForm(forms.Form):
    domain = forms.CharField(
        max_length=255,
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
            attrs={
                "type": "datetime-local",
                "class": INPUT_CLASS,
            },
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
            attrs={
                "type": "time",
                "class": INPUT_CLASS,
            },
            format="%H:%M",
        ),
    )

    def clean(self):
        cleaned = super().clean()
        schedule_type = cleaned.get("schedule_type")
        if schedule_type == "once" and not cleaned.get("scheduled_at"):
            self.add_error("scheduled_at", "Please select a date and time.")
        if schedule_type == "recurring" and not cleaned.get("recurrence_time"):
            self.add_error("recurrence_time", "Please select a time for the recurring scan.")
        return cleaned
