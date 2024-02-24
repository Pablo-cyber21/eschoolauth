from rest_framework.decorators import api_view
from rest_framework.response import Response

from .serializers import UserSerializer
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User

from django.shortcuts import get_object_or_404


# Api for login
@api_view(["POST"])
def login(request):
    # Get username from db and prep it for authorization.
    # Use the username as a first level of authorization
    user = get_object_or_404(User, username=request.data["username"])

    # Second phase of authorization is password.
    # Just incase the username "did not work".
    if not user.check_password(request.data["password"]):
        # If the password is wrong then tell the the user was not found.(No specifics on whether one was right or not)
        return Response({"detail": "Not Found"}, status=status.HTTP_404_NOT_FOUND)

    # If all is right identify the token's user.
    token, created = Token.objects.get_or_create(user=user)

    # map the db data and bring it.
    serializer = UserSerializer(instance=user)
    return Response({"token": token.key, "user": serializer.data})


# API for sign up
@api_view(["POST"])
def sign_up(request):
    # Grab the data to be captured in the serializer in a post.
    serializer = UserSerializer(data=request.data)

    # If the data is valid / true,
    if serializer.is_valid():
        # save it,
        serializer.save()
        # Get the User model in particular the username.
        user = User.objects.get(username=request.data["username"])
        # Protected password for user
        user.set_password(request.data["password"])
        user.save()
        # Plus the token
        token = Token.objects.create(user=user)

        return Response({"token": token.key, "user": serializer.data})

    # if it is not valid.
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated


# API for the test token
# Makes sure that the user token is actually authenticated with their token.
@api_view(["GET"])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed for {}".format(request.user.email))
