from django.forms import ModelForm
from nvd.models import Vulnerability, Assessment

class AssessmentForm(ModelForm):
    class Meta:
        model = Assessment
        fields = ('author', 'service', 'vulnerable_products', 'workaround', 'permanent_measures', 'policy')