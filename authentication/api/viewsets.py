from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password

from authentication.models import User
from .serializers import UserSerializer
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
