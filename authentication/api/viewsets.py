from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password
from django.contrib.auth import update_session_auth_hash

from authentication.models import User
from .serializers import ChangePasswordSerializer, UserSerializer
from utils.validation.strong_password import is_strong_password

class CreateUserView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny,]
    queryset = User.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not is_strong_password(request.data["password"]):
            return Response(
                {"message": "Invalid password format."},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        hashed_password = make_password(request.data["password"])

        user = User.objects.create(
            email=request.data["email"],
            password=hashed_password,
        )

        user.save()

        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                "id": user.id,
                "email": user.email,
            },
            status=status.HTTP_201_CREATED,
            headers=headers,
        )


class ChangePasswordAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def put(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            if not is_strong_password(request.data["new_password"]):
                return Response(
                    {"message": "Invalid password format."},
                    status=status.HTTP_422_UNPROCESSABLE_ENTITY,
                )

            user = request.user

            if user.check_password(serializer.data.get('old_password')):
                user.set_password(serializer.data.get('new_password'))
                user.save()
                update_session_auth_hash(request, user)

                return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)

            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
