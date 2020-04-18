from django.urls import path
from accounts.views import sample_api
from accounts import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
# pip install djangorestframework-simplejwt

urlpatterns = [
    path('register/', views.Registration.as_view()),
    path('login/', views.Login.as_view()),
    path('logout/', views.Logout.as_view()),
    path('password_change/', views.PasswordChange.as_view()),
    path('sample/', sample_api),

    #path('api/token/', views.LoginView.as_view(), name='token_obtain_pair'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    #path('api/token/refresh/', views.TokenRefreshView.as_view(), name='token_refresh'),

]
