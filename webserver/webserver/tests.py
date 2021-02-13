from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

import os

import logging
logger = logging.getLogger(__name__)

ROOT_LOGIN_URL = reverse('login')
ROOT_LOGOUT_URL = reverse('logout')
ROOT_UPDATE_URL = reverse('update')
ROOT_USERINFO_URL = reverse('userinfo')
ROOT_REFRESH_TOKEN_URL = reverse('refresh_token')
ROOT_NEW_TOKEN_URL = reverse('new_token')
ROOT_REVOKE_TOKEN_URL = reverse('revoke_token')
ROOT_GENERATE_CERT_URL = reverse('generate_cert')
ROOT_VERIFY_CERT_URL = reverse('verify_cert')
ROOT_REVOKE_CERT_URL = reverse('revoke_cert')
ROOT_STATUS_CERT_URL = reverse('status_cert')

class WebserverTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_login(self):
        payload = {'username': 'test', 'password': '123'}
        resp = self.client.post(ROOT_LOGIN_URL, payload)
        self.assertEqual(status.HTTP_200_OK, resp.status_code)
        result = resp.json()
        token = result['access_token']
        payload = {'last_name': 'chang', 'first_name': 'mei', 'email': 'mei@google.com', 'token': token}
        resp = self.client.post(ROOT_UPDATE_URL, payload)
        self.assertEqual(status.HTTP_200_OK, resp.status_code)
        resp = self.client.get(ROOT_USERINFO_URL, HTTP_AUTHORIZATION='{}'.format(token))
        self.assertEqual(status.HTTP_200_OK, resp.status_code)
        result = resp.json()
        self.assertEqual(result['last_name'], 'chang')
        payload = {'token': token}
        resp = self.client.post(ROOT_LOGOUT_URL, payload)
        self.assertEqual(status.HTTP_200_OK, resp.status_code)
        


