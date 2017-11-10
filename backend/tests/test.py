from flask import Flask
from flask_testing import TestCase

class MyTestJSON(TestCase):

    def create_app(self):
        backend = Flask(__name__)
        backend.config.from_object('config')
        backend.config['TESTING'] = True
        return backend

    def test_some_json(self):
        response = self.client.get('/login')
        self.assertEquals(response.json, dict(success=True))



class MyTestDB(TestCase):

    def create_app(self):
        backend = Flask(__name__)
        backend.config.from_object('config')
        backend.config['SQLALCHEMY_DATABASE_URI'] = "sqlite://db-test.db"
        backend.config['TESTING'] = True
        self.db = SQLAlchemy(backend)
        return backend

    def setUp(self):
        self.db.create_all()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()

if __name__ == '__main__':
    unittest.main()