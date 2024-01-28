from django.contrib.auth.hashers import make_password
from django.urls import reverse
from rest_framework.test import APITestCase

from authentication.models import User


class TestRegister(APITestCase):
    def setUp(self) -> None:
        self.email = 'juvenal@test.com'
        self.password = 'S6y6@9iP5Q&r5BQx'
        self.hashed_password = make_password(self.password)

        User.objects.create(email=self.email, password=self.hashed_password)

        return super().setUp()

    def test_should_be_able_to_register(self):
        url = reverse('create_user')

        response = self.client.post(
            url, {'email': 'juvenal2@test.com', 'password': self.password}, format='json'
        )

        self.assertTrue(response.status_code == 201)
        self.assertTrue(response.data['id'] != None)
        self.assertTrue(response.data['email'] != None)

    def test_should_not_be_able_to_register_when_email_already_in_use(self):
        url = reverse('create_user')

        response = self.client.post(
            url, {'email': self.email, 'password': self.password}, format='json'
        )

        self.assertTrue(response.status_code == 400)
        self.assertTrue(len(response.data['email']) > 0)

    def test_should_not_be_able_to_register_with_invalid_password_format(self):
        url = reverse('create_user')

        response = self.client.post(
            url, {'email': 'juvenal2@test.com', 'password': '123456789'}, format='json'
        )

        self.assertTrue(response.status_code == 422)

    def test_should_not_be_able_to_register_without_email(self):
        url = reverse('create_user')

        response = self.client.post(
            url, {'password': self.password}, format='json'
        )

        self.assertTrue(response.status_code == 400)
        self.assertTrue(len(response.data['email']) > 0)

    def test_should_not_be_able_to_register_without_password(self):
        url = reverse('create_user')

        response = self.client.post(
            url, {'email': self.email}, format='json'
        )

        self.assertTrue(response.status_code == 400)
        self.assertTrue(len(response.data['password']) > 0)
