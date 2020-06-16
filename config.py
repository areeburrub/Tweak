import os

S3_BUCKET = os.environ.get("S3_BUCKET")
S3_KEY = os.environ.get("S3_KEY")
S3_SECRET = os.environ.get("S3_SECRET_ACCESS_KEY")
S3_REGION = os.environ.get("S3_REGION")


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