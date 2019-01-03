import json
import itertools

from django.http.response import HttpResponse
from django.shortcuts import render
from django.conf import settings
import os
from nvd.models import Vulnerability

file_path = os.path.join(settings.FILES_DIR, 'nvdcve-1.0-recent.json')
f = open(file_path, 'r')

json_dict_first = json.load(f)


def index(request):
    
    result_cve_id = []
    result_base_score = []
    result_attack_vector = []
    result_cwe_type = []
    result_description = []
    result_published_date = []
    result_last_modified_date = []
    result_vendor_name = []
    result_product_name = []
    result_vulnerability = []

    for i in range(len(json_dict_first["CVE_Items"])):
        while True:
            try:
                cve_id = json_dict_first["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"]
                base_score = json_dict_first["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                attack_vector = json_dict_first["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                cwe_type = json_dict_first["CVE_Items"][i]["cve"]["problemtype"] ["problemtype_data"][0]["description"][0]["value"]
                description = json_dict_first["CVE_Items"][i]["cve"]["description"]["description_data"][0]["value"]
                published_date = json_dict_first["CVE_Items"][i]["publishedDate"].replace('T', ' ').replace('Z', ' ')
                last_modified_date = json_dict_first["CVE_Items"][i]["lastModifiedDate"].replace('T', ' ').replace('Z', ' ')
                vendor_name = json_dict_first["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
                product_name = json_dict_first["CVE_Items"][i]["cve"]["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0]["product_name"]

                result_cve_id.append(cve_id)
                result_base_score.append(base_score)
                result_attack_vector.append(attack_vector)
                result_cwe_type.append(cwe_type)
                result_description.append(description)
                result_published_date.append(published_date)
                result_last_modified_date.append(last_modified_date)
                result_vendor_name.append(vendor_name)
                result_product_name.append(product_name)
                result_vulnerability  = list(map(list, itertools.zip_longest(result_cve_id, result_base_score, result_attack_vector, result_cwe_type, result_description, result_published_date, result_last_modified_date, result_vendor_name, result_product_name)))

                break
            except KeyError:
                break
            except IndexError:
                break


    for j in range(len(result_vulnerability)):
        data = Vulnerability()
        data.cve_id = result_vulnerability[j][0]
        data.base_score = result_vulnerability[j][1]
        data.attack_vector = result_vulnerability[j][2]
        data.cwe_type = result_vulnerability[j][3]
        data.description = result_vulnerability[j][4]
        data.published_date = result_vulnerability[j][5]
        data.last_modified_date = result_vulnerability[j][6]
        data.vendor_name = result_vulnerability[j][7]
        data.product_name = result_vulnerability[j][8]
        data.save()

    vulnerabilities = Vulnerability.objects.all().order_by('id')
    return render(request, 'nvd/index.html', {'vulnerabilities': vulnerabilities})

    