from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import EmailMessage

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


class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            current_site = get_current_site(request)
            subject = 'Reset Your Password'
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = user.email
            email = EmailMessage(subject, message, to=[to_email])
            email.send()
            return Response({'detail': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'No user found with that email address.'}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            user.set_password(new_password)
            user.save()

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response({'access_token': access_token}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid token or user not found.'}, status=status.HTTP_400_BAD_REQUEST)
