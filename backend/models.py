
from backend import db
from config import LULEBO_SECRET_KEY

from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

crypto = Fernet(LULEBO_SECRET_KEY)

# TODO: What is index=True?

class UserNotFoundError(ValueError):
    '''Raise if a specific user cannot be found in db.'''

class User(db.Model):
    id       = db.Column(db.Integer     , primary_key=True)
    username = db.Column(db.String(64)  , index=True, unique=True)
    password = db.Column(db.String(160) , unique=False)
    email    = db.Column(db.String(120) , unique=True)

    lulebo_username_cipher = db.Column(db.String(120))
    lulebo_password_cipher = db.Column(db.String(120))
    lulebo_session_id      = db.Column(db.String(256))

    uuid = db.Column(db.String(120))

    @property
    def lulebo_password(self):
        cipher_bytes = str.encode(self.lulebo_password_cipher, 'utf-8')
        clear_bytes  = crypto.decrypt(cipher_bytes)
        return clear_bytes.decode('utf-8')

    @lulebo_password.setter
    def lulebo_password(self, val):
        clear_bytes  = str.encode(val, 'utf-8')
        cipher_bytes = crypto.encrypt(clear_bytes)
        self.lulebo_password_cipher = cipher_bytes.decode('utf-8')

    @property
    def lulebo_username(self):
        cipher_bytes = str.encode(self.lulebo_username_cipher, 'utf-8')
        clear_bytes  = crypto.decrypt(cipher_bytes)
        return clear_bytes.decode('utf-8')

    @lulebo_username.setter
    def lulebo_username(self, val):
        clear_bytes  = str.encode(val, 'utf-8')
        cipher_bytes = crypto.encrypt(clear_bytes)
        self.lulebo_username_cipher = cipher_bytes.decode('utf-8')

    @staticmethod
    def authenticate(name, password):
        try:
            user = User.get_by_name(name)
        except UserNotFoundError:
            return False
        is_validated = check_password_hash(user.password, password)
        return is_validated

    @staticmethod
    def get_by_id(id):
        user = User.query.filter_by(id=id).first()
        if user is None:
            raise UserNotFoundError()
        return user

    @staticmethod
    def get_by_name(name):
        user = User.query.filter_by(username=name).first()
        if user is None:
            raise UserNotFoundError()
        return user

    @staticmethod
    def get_by_email(email):
        user = User.query.filter_by(email=email).first()
        if user is None:
            raise UserNotFoundError()
        return user

    @staticmethod
    def get_by_uuid(uuid):
        user = User.query.filter_by(uuid=uuid).first()
        if user is None:
            raise UserNotFoundError()
        return user

    @staticmethod
    def exists(name):
        try:
            user = User.get_by_name(name)
        except UserNotFoundError:
            return False
        return True

    @staticmethod
    def exists_email(email):
        try:
            user = User.get_by_email(email)
        except UserNotFoundError:
            return False
        return True

    def __init__(self, password, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(password, self.password)

    @property
    def is_active(self):
        '''Return False if user is not-activated, has been suspended etc.'''
        return True

    @property
    def is_anonymous(self):
        '''Return True if user is a guest, else false.'''
        return False

    @property
    def is_authenticated(self):
        return True

    def get_id(self):
        return str(self.id)
    
    def __repr__(self):
        return '<User %r>' % (self.username)
