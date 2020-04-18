from rest_framework import serializers
from accounts.models import CustomUser
from django.contrib.auth.models import User
from django.contrib.auth import password_validation
from django.contrib.auth.models import update_last_login
from django.contrib.auth import authenticate


#JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
#JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def save(self):
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password': 'passwords must match'})

        user = CustomUser.objects.create_user(
            email=self.validated_data['email'],
        )
        user.set_password(password)
        user.save()

        return user


# for jwt-authentication only
"""
class UserLoginSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        user = authenticate(email=email, password=password)
        if user is None:
            raise serializers.ValidationError('Invalid Credentials')

        try:
            #payload = JWT_PAYLOAD_HANDLER(user)
            #jwt_token = JWT_ENCODE_HANDLER(payload)
            #update_last_login(None, user)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError(
                'User with given email and password does not exists'
            )
        return {
            'email': user.email,
            'token': jwt_token
        }

"""


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_current_password(self, value):
        email = self.context['user']
        user = CustomUser.objects.get(email=email)
        print(user)
        if not user.check_password(value):
            raise serializers.ValidationError('Current password does not match')

        return value

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value
