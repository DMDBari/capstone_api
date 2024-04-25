import os

# Get the base directory of this folder
basedir = os.path.abspath(os.path.dirname(__file__))
# C:\Users\Dillon\Documents\coding_temple\week6\flask-blog-api

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    