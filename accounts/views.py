from django.contrib.auth import authenticate, logout
from rest_framework.authtoken.models import Token
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from accounts.serializers import RegistrationSerializer, PasswordChangeSerializer
from rest_framework import serializers


class Registration(APIView):
    """
    A view for registering the users
    """

    def post(self, request, format=None):
        serializer = RegistrationSerializer(data=request.query_params)
        data = {}
        if serializer.is_valid():
            try:
                #print(serializer.validated_data)
                account = serializer.save()
            except serializers.ValidationError as error:
                raise error
            else:
                data['email'] = account.email
                data['first_name'] = account.first_name
                data['response'] = 'successfully registered a new user'
                return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):

    def post(self, request, format=None):
        email = request.query_params.get('email')
        password = request.query_params.get('password')

        user = authenticate(username=email, password=password)
        if not user:
            return Response(
                {'error': 'Invalid Credentials'},
                status=status.HTTP_404_NOT_FOUND
            )

        token, created = Token.objects.get_or_create(user=user)
        return Response(
            {'token': token.key},
            status=status.HTTP_200_OK
        )


"""
# for jwt-token
class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        response = {
            'success': 'True',
            'message': 'User logged in successfully',
            'token': serializer.data['token'],
        }
        return Response(response, status=status.HTTP_200_OK)

"""


class PasswordChange(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        user = request.user
        print(user)
        context = {'user': request.user}
        serializer = PasswordChangeSerializer(data=request.query_params, context=context)

        serializer.is_valid(raise_exception=True)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class Logout(APIView):
    def post(self, request):
        logout(request)
        data = {'success': 'Sucessfully logged out'}
        return Response(data=data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def sample_api(request):
    data = {'sample_data': 123}
    return Response(data, status=status.HTTP_200_OK)
