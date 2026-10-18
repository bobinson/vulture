# held-out heldout_06 (CWE-22): a route table of path entries, one route string naming user data
from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("about/", views.about, name="about"),
    path("api/user-data/", views.data_view, name="data"),
    path("logout/", views.signout_view, name="logout"),
]
