from flask import Flask
from flask_testing import TestCase

import os
import json

import backend.util

from config import gen_db_path

from backend import create_app
from backend import db

def default_user():
    return {
        'username'       : 'test_user',
        'password'       : 'test_pass',
        'email'          : '',
        'lulebo_username': '',
        'lulebo_password': ''
    };

class MyTestJSON(TestCase):
    '''
    This is for the cases where the pre-populated test database is sufficient.
    '''

    def post_json(self, url, **kwargs):
        '''
        Keyword arguments:
        data         : dict (or compatible object)
        content_type : will be set to json if not provided
        '''
        try   : kwargs['content_type']
        except: kwargs['content_type'] = 'application/json'
        
        try    : kwargs['data'] = json.dumps(kwargs['data'])
        except : pass
        
        return self.client.post(url, **kwargs)

    def create_app(self):
        config = {
            'SQLALCHEMY_DATABASE_URI': gen_db_path('test'),
            'TESTING'                : True
        }
        return create_app(config)

    def test_hi(self):
        response = self.client.get('/hi')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, dict(msg='Hello!', status='ok'))

    def test_secret_hi(self):
        response = self.client.get('/secret-hi')
        self.assertEqual(response.status_code, 401)

    def test_login(self):
        payload = dict(username='test_user', password='test_pass')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, dict(msg='Success', status='ok'))

        payload = dict(username='test_user', password='wrong_pass')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, dict(msg='Wrong username and/or password', status='error'))

        payload = dict(username='wrong_user', password='test_pass')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, dict(msg='Wrong username and/or password', status='error'))

        payload = dict(username='test_user', password='')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, dict(msg='Wrong username and/or password', status='error'))

        payload = dict(username='', password='')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, dict(msg='Wrong username and/or password', status='error'))

        payload = dict(password='test_pass')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, dict(msg='Missing username', status='error'))

        payload = dict(username='test_user')
        response = self.post_json('/login', data=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, dict(msg='Missing password', status='error'))




class MyTestDB(TestCase):
    '''
    This is for the cases where database functionality is required.
    '''

    def create_app(self):
        config = {
            'SQLALCHEMY_DATABASE_URI': gen_db_path('test-regen'),
            'TESTING'                : True
        }
        backend = create_app(config)
        return backend

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    # def test_add_user(self):
    #     backend.util.add_user(db, default_user())
        # TODO: Verify that user exists.

    


if __name__ == '__main__':
    unittest.main()