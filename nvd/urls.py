from django.urls import path
from nvd import views

app_name = 'nvd'
urlpatterns = [
    path('', views.index, name='index'),     
]