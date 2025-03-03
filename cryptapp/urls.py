from django.urls import path
from .views import *

urlpatterns = [
    path('encode/', encode),
    path('decode/', decode),
]