import json
import itertools
from allauth.account import views
from django.http.response import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.conf import settings
import os
from nvd.models import Vulnerability, Assessment
from nvd.forms import AssessmentForm
from django.db import IntegrityError, transaction

from django.views.generic.list import ListView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin


# file_path = os.path.join(settings.FILES_DIR, 'nvdcve-1.0-2018.json')
# f = open(file_path, 'r')

# json_dict_first = json.load(f)

@login_required
def index(request):
    
    # result_cve_id = []
    # result_base_score = []
    # result_attack_vector = []
    # result_cwe_type = []
    # result_description = []
    # result_published_date = []
    # result_last_modified_date = []
    # result_vendor_name = []
    # result_product_name = []
    # result_vulnerability = []

    # for i in range(len(json_dict_first["CVE_Items"])):
    #     while True:
    #         try:
    #             cve_id = json_dict_first["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"]
    #             base_score = json_dict_first["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
    #             attack_vector = json_dict_first["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
    #             cwe_type = json_dict_first["CVE_Items"][i]["cve"]["problemtype"] ["problemtype_data"][0]["description"][0]["value"]
    #             description = json_dict_first["CVE_Items"][i]["cve"]["description"]["description_data"][0]["value"]
    #             published_date = json_dict_first["CVE_Items"][i]["publishedDate"].replace('T', ' ').replace('Z', ' ')
    #             last_modified_date = json_dict_first["CVE_Items"][i]["lastModifiedDate"].replace('T', ' ').replace('Z', ' ')
    #             vendor_name = json_dict_first["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
    #             product_name = json_dict_first["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["product_name"]

    #             result_cve_id.append(cve_id)
    #             result_base_score.append(base_score)
    #             result_attack_vector.append(attack_vector)
    #             result_cwe_type.append(cwe_type)
    #             result_description.append(description)
    #             result_published_date.append(published_date)
    #             result_last_modified_date.append(last_modified_date)
    #             result_vendor_name.append(vendor_name)
    #             result_product_name.append(product_name)
    #             result_vulnerability  = list(map(list, itertools.zip_longest(result_cve_id, result_base_score, result_attack_vector, result_cwe_type, result_description, result_published_date, result_last_modified_date, result_vendor_name, result_product_name)))

    #             break
    #         except KeyError:
    #             break
    #         except IndexError:
    #             break


    # for j in range(len(result_vulnerability)):
    #     while True:
    #         try:
    #             with transaction.atomic():
    #                 data = Vulnerability()
    #                 data.cve_id = result_vulnerability[j][0]
    #                 data.base_score = result_vulnerability[j][1]
    #                 data.attack_vector = result_vulnerability[j][2]
    #                 data.cwe_type = result_vulnerability[j][3]
    #                 data.description = result_vulnerability[j][4]
    #                 data.published_date = result_vulnerability[j][5]
    #                 data.last_modified_date = result_vulnerability[j][6]
    #                 data.vendor_name = result_vulnerability[j][7]
    #                 data.product_name = result_vulnerability[j][8]
    #                 data.save()
    #                 break
    #         except IntegrityError:
    #             break

    vulnerabilities = Vulnerability.objects.all().order_by('id')
    return render(request, 'nvd/index.html', {'vulnerabilities': vulnerabilities})


class AssessmentList(LoginRequiredMixin, ListView):
    context_object_name='assessments'
    template_name='nvd/assessment_list.html'
    paginate_by = 5


    def get(self, request, *args, **kwargs):
        vulnerability = get_object_or_404(Vulnerability, pk=kwargs['vulnerability_id'])  
        assessments = vulnerability.assessments.all().order_by('id')   
        self.object_list = assessments

        context = self.get_context_data(object_list=self.object_list, vulnerability=vulnerability)    
        return self.render_to_response(context)

@login_required
def assessment_edit(request, vulnerability_id, assessment_id=None):
    vulnerability = get_object_or_404(Vulnerability, pk=vulnerability_id)  
    if assessment_id: 
        assessment = get_object_or_404(Assessment, pk=assessment_id)
    else:              
        assessment = Assessment()

    if request.method == 'POST':
        form = AssessmentForm(request.POST, instance=assessment)  
        if form.is_valid():    
            assessment = form.save(commit=False)
            assessment.vulnerability = vulnerability
            assessment.save()
            return redirect('nvd:assessment_list', vulnerability_id=vulnerability_id)
    else:
        form = AssessmentForm(instance=assessment)  

    return render(request, 'nvd/assessment_edit.html', dict(form=form, vulnerability_id=vulnerability_id, assessment_id=assessment_id))

@login_required
def assessment_del(request, vulnerability_id, assessment_id):
    assessment = get_object_or_404(Assessment, pk=assessment_id)
    assessment.delete()
    return redirect('nvd:assessment_list', vulnerability_id=vulnerability_id)

