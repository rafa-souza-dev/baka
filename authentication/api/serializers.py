from rest_framework import serializers

from authentication import models

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, max_length=16)

    class Meta:
        model = models.User
        fields = ('id', 'email', 'password')


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
