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

    def create_app(self):
        config = {
            'SQLALCHEMY_DATABASE_URI': gen_db_path('test'),
            'TESTING'                : True
        }
        return create_app(config)

    def test_login(self):
        payload=dict(username='test_user', password='test_pass')
        response = self.client.post('/login', data=json.dumps(payload), content_type='application/json')
        print('response', response)
        self.assertEqual(response.json, dict(msg='Success', status='ok'))






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