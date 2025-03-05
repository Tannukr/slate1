from django.urls import path
from .views import LoginView, DashboardView

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("dashboard/<str:role>/<int:userid>/", DashboardView.as_view(), name="dashboard"),  
]
