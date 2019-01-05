from django.db import models

class Vulnerability(models.Model):
    cve_id = models.CharField('CVE', max_length=255, blank=True, unique=True)
    base_score = models.FloatField('Base Score', blank=True, default=0)
    attack_vector = models.CharField('Attack Vector', max_length=255, blank=True)
    cwe_type = models.CharField('CWE Type', max_length=255, blank=True)
    description = models.TextField('Description', max_length=1000, blank=True)
    published_date = models.CharField('Published Date', max_length=255, blank=True)
    last_modified_date = models.CharField('Last Modified Date', max_length=255,  blank=True)
    vendor_name = models.CharField('Vendor Name', max_length=255, blank=True)
    product_name = models.CharField('Product Name', max_length=255, blank=True)
    affected_version = models.CharField('Affected Version', max_length=255, blank=True)

    def __str__(self):
        return self.cve_id

class Assessment(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, verbose_name='Vulnerability', related_name='assessments', on_delete=models.PROTECT)
    author = models.CharField('Author', max_length=30)
    service = models.CharField('Service', max_length=30, blank=True)
    vulnerable_products = models.CharField('Vulnerable Products', max_length=255, blank=True)
    workaround = models.TextField('Workaround', max_length=1000, blank=True)
    permanent_measures = models.TextField('Permanent Measures', max_length=1000, blank=True)
    policy = models.TextField('Policy', max_length=1000, blank=True)
    created_at = models.DateTimeField('Created At', auto_now_add=True)
 

    def __str__(self):
        return self.vulnerable_products

