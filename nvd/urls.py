from django.urls import path
from nvd import views

app_name = 'nvd'
urlpatterns = [
    path('', views.IndexList.as_view(), name='index'),
    path('assessment/<int:vulnerability_id>/', views.AssessmentList.as_view(), name='assessment_list'),
    path('assessment/add/<int:vulnerability_id>/', views.assessment_edit, name='assessment_add'), 
    path('assessment/mod/<int:vulnerability_id>/<int:assessment_id>/', views.assessment_edit, name='assessment_mod'),  
    path('assessment/del/<int:vulnerability_id>/<int:assessment_id>/', views.assessment_del, name='assessment_del'),  
]