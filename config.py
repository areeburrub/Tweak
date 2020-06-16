import os

AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_DEFAULT_REGION = os.environ['AWS_DEFAULT_REGION']
S3_BUCKET_NAME = os.environ['S3_BUCKET_NAME']

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