import secrets
import os
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin
import time
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView


app = Flask(__name__)


#config
app.config.from_object(os.environ['APP_SETTING'])

#Bootstrap for some stylings in login and signup page
Bootstrap(app)

#Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#DataBase initalized
db = SQLAlchemy(app)


roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

#USER Table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean, unique=False, default=True)
    profile_picture = db.Column(db.String(20), nullable=False, default='default.png')
    roles = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )

    def __repr__(self):
        return (self.username)



#Roles Table
class Role(RoleMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40))

    def __repr__(self):
        return (self.name)





#Login Manager Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Login Form WT FORM
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4,max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4,max=80)])
    remember = BooleanField('remember me')

#Singup Form Singup form
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email('Invalid Email')])
    username = StringField('username', validators=[InputRequired(), Length(min=4,max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4,max=80)])
    confirm  = PasswordField('confirm password', validators=[InputRequired(), EqualTo('password')])
    remember = BooleanField('remember me')
    profile_pic = FileField('profile picture', validators=[FileAllowed(['jpg','png'])])

class UpdateAcountForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email('Invalid Email')])
    username = StringField('username', validators=[InputRequired(), Length(min=4,max=15)])

#Link for index page
@app.route('/')
def index():
    return render_template('index.html')



#link for login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard', pro = current_user.username))
        return render_template('login.html', form=form, msg='Wrong Username or Password')
        #return '<H1>' + form.username.data + ' ' + form.password.data + '</H1>'

    return render_template('login.html', form=form)


#Save Profile Pictures
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    form_picture.save(picture_path)

    return picture_fn


#Link to Singup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        ppic = save_picture(form.profile_pic.data)
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, profile_picture=ppic)
        exists = db.session.query(db.exists().where(User.username == form.username.data )).scalar()
        if (exists):
            return render_template('signup.html', form=form, msg='username already taken')
        else:
            db.session.add(new_user)
            db.session.commit()
        
        return render_template('login.html', form=form, msg='New account created')
        #return '<H1>' + form.username.data + ' ' +form.email.data+' '+ form.password.data + '</H1>'

    return render_template('signup.html', form=form)




#Link to Dashboard
@app.route('/profile/<string:pro>')
@login_required
def dashboard(pro):
    user = User.query.filter_by(username=pro).first()
    image_file = url_for('static',filename='profile_pics/'+user.profile_picture)
    currentuser = User.query.filter_by(username=pro).one()
    return render_template('profile.html', admin=current_user.admin, image_file = image_file, name = str(current_user.username), profile = str(currentuser))

#Link to Posts
@app.route('/posts')
@login_required
def posts():
    return render_template('posts.html', name = current_user.username)




#Link to Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#adding database view on admin page


################################# ADMIN CODE ####################################
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):

        if (current_user.is_anonymous == False):
            UserRole = current_user.admin
            if (UserRole == True):
                return True
            elif(UserRole == False):
                return False
        else:
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        form = LoginForm()
        return render_template('login.html', form=form, msg='You are not an Admin!, \n Please Login')
 

class MyModelView(ModelView):
    def is_accessible(self):

        return current_user.is_authenticated
        UserRole = current_user.admin
        if (UserRole == True):
            return True
        elif(UserRole == False):
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        form = LoginForm()
        return render_template('login.html', form=form, msg='You are not an Admin!, \n Please Login')
        

admin = Admin(app, index_view = MyAdminIndexView())

################################################################################################

admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Role, db.session))

if __name__ == '__main__':
    app.run()