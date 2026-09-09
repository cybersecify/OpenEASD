from django.contrib import admin

from .models import Domain, DomainAuthorization


class DomainAuthorizationInline(admin.StackedInline):
    model = DomainAuthorization
    extra = 0
    can_delete = True


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ["name", "is_primary", "is_active", "auth_status", "added_at"]
    list_filter = ["is_active", "is_primary", "authorization__auth_type"]
    search_fields = ["name"]
    inlines = [DomainAuthorizationInline]

    @admin.display(description="Authorization")
    def auth_status(self, obj):
        try:
            return obj.authorization.get_auth_type_display()
        except DomainAuthorization.DoesNotExist:
            return "⚠ Not authorized"
