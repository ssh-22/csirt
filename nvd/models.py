from django.db import models

class Vulnerability(models.Model):
    cve_id = models.CharField('CVE', max_length=255, blank=True)
    base_score = models.FloatField('Base Score', blank=True, default=0)
    attack_vector = models.CharField('Attack Vector', max_length=255, blank=True)
    cwe_type = models.CharField('CWE Type', max_length=255, blank=True)
    description = models.TextField('Description', max_length=1000, blank=True)
    published_date = models.TextField('Published Date', max_length=255, blank=True)
    last_modified_date = models.TextField('Last Modified Date', max_length=255,  blank=True)
    vendor_name = models.CharField('Vendor Name', max_length=255, blank=True)
    product_name = models.CharField('Product Name', max_length=255, blank=True)
    affected_version = models.CharField('Affected Version', max_length=255, blank=True)


    def __str__(self):
        return self.cve_id
