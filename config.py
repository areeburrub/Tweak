import os

#default congig
class BaseConfig(object):
    DEBUG=False
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    TESTING = False
    SECRET_KEY = 'Thisissecret'
    CSRF_ENABLED = True
    USER_ENABLE_EMAIL = False

class DevConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False