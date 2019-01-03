from django.contrib import admin
from nvd.models import Vulnerability


class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('id', 'cve_id', 'base_score', 'attack_vector', 'cwe_type', 'description', 'published_date', 'last_modified_date', 'vendor_name', 'product_name', 'affected_version', )
    list_display_links = ('id', 'cve_id', )


admin.site.register(Vulnerability)