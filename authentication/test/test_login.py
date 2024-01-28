from django.contrib.auth.hashers import make_password
from django.urls import reverse
from rest_framework.test import APITestCase

from authentication.models import User


class TestLogin(APITestCase):
    def setUp(self) -> None:
        self.email = 'juvenal@test.com'
        self.password = 'S6y6@9iP5Q&r5BQx'
        self.hashed_password = make_password(self.password)

        User.objects.create(email=self.email, password=self.hashed_password)

        return super().setUp()

    def test_should_be_able_to_authenticate(self):
        url = reverse('token_obtain_pair')

        response = self.client.post(
            url, {'email': self.email, 'password': self.password}, format='json'
        )

        self.assertTrue(response.status_code == 200)
        self.assertTrue(response.data['access'] != None)
        self.assertTrue(response.data['refresh'] != None)

    def test_should_not_be_able_to_authenticate_with_invalid_credentials(self):
        url = reverse('token_obtain_pair')

        response = self.client.post(
            url, {'email': 'juvenal@test.com', 'password': 'S6y6@9i12Q&46BQx'}, format='json'
        )

        self.assertTrue(response.status_code == 401)

    def test_should_not_be_able_to_authenticate_without_email(self):
        url = reverse('token_obtain_pair')

        response = self.client.post(
            url, {'password': 'S6y6@9i12Q&46BQx'}, format='json'
        )

        self.assertTrue(response.status_code == 400)
        self.assertTrue(len(response.data['email']) > 0)

    def test_should_not_be_able_to_authenticate_without_password(self):
        url = reverse('token_obtain_pair')

        response = self.client.post(
            url, {'email': 'juvenal@test.com'}, format='json'
        )

        self.assertTrue(response.status_code == 400)
        self.assertTrue(len(response.data['password']) > 0)
