import secrets
import os
from flask import Flask, render_template, redirect, url_for, flash, request,jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin
import time
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from resource import get_bucket, get_buckets_list
from datetime import datetime
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION, S3_BUCKET_NAME
from filters import datetimeformat
from sqlalchemy import desc
from sqlalchemy.sql import text
from flask_marshmallow import Marshmallow

app = Flask(__name__)
app.jinja_env.filters['datetimeformat'] = datetimeformat

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
ma = Marshmallow(app)



class Posts(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(30), nullable=False)
    post_by = db.Column(db.String(15), nullable=False)
    post_title = db.Column(db.String(80), nullable=False)
    post_body = db.Column(db.String(25000), nullable=False)
    post_created = db.Column(db.DateTime, default = datetime.utcnow)

#The Marshmallow Schema
class PostSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Posts
    id = ma.auto_field()
    post_title = ma.auto_field()
    post_body = ma.auto_field()
    post_id = ma.auto_field()
    post_created = ma.auto_field()


#USER Table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean, unique=False, default=False)
    profile_picture = db.Column(db.String(70), nullable=False, default='url_for(\'static\',filename=\'default.png\')')
    about = db.Column(db.String(120), unique=False)

    def __repr__(self):
        return (self.username)  
    

#The Marshmallow Schema
class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
    id = ma.auto_field()
    username = ma.auto_field()
    about = ma.auto_field()
    

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
    profile_pic = FileField(validators=[FileAllowed(['jpg','png'])])
    about = TextAreaField(validators=[Length(max=150)])



#Save Profile Pictures
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    #picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn) #Local Image Path
    my_bucket = get_bucket()
    my_bucket.put_object(Key=picture_fn, Body=form_picture, ACL='public-read')
    #form_picture.save(picture_path) #for local image save
    return 'https://diyareeb.s3.us-east-2.amazonaws.com/' + picture_fn #for AWS IMAGE SAVE


#Link for index page
@app.route('/')
def index():
    if (current_user.is_anonymous == False):
        return redirect(url_for('dashboard', pro = current_user.username))
    else:
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
        return redirect(url_for('login.html', form=form, msg='Wrong Username or Password'))
    return render_template('login.html', form=form)


#Link to Singup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        if (form.profile_pic.data):
            ppic = save_picture(form.profile_pic.data)
        else:
            ppic = url_for('static',filename='profile_pics/default.png')
            about = 'This is a about' 
            
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, profile_picture=ppic)
        exists = db.session.query(db.exists().where(User.username == form.username.data )).scalar()
        if (exists):
            return render_template('signup.html', form=form, msg='username already taken')
        else:
            db.session.add(new_user)
            db.session.commit()
        
        return render_template('login.html', form=form, msg='New account created')
        
    return render_template('signup.html', form=form)



@app.route('/update/<string:idp>', methods=['GET', 'POST'])
@login_required
def update(idp):
    form = LoginForm()
    if (idp == current_user.username):
        if (request.method == 'POST'):
            user = User.query.filter_by(username=idp).first()
            if (request.files['ppic']):
                ppic = save_picture(request.files['ppic'])
            else:
                ppic = current_user.profile_picture
            
            user.profile_picture = ppic
            user.about = request.form['about']
            try:
                db.session.commit()
                return redirect(url_for('dashboard', pro = current_user.username))
            except:
                return render_template('login.html', form=form, msg='An Error Occured! Retry After Reload')
 
        else:
            user = User.query.filter_by(username=idp).first()
            image_file = user.profile_picture
            return render_template('update.html', idp=idp, msg='You are not user of this account, \n Please Login', image_file = image_file, profile = str(current_user.username), about=current_user.about)
 
    else:
        
        return render_template('login.html', form=form, msg='You are not an Admin!, \n Please Login')


@app.route('/profile/')
@login_required
def profile_login_check():
    if (current_user.is_anonymous == False):

        return redirect(url_for('login', msg = "Please Login to Continue"))



#Link to Dashboard
@app.route('/profile/<string:pro>')
@login_required
def dashboard(pro):
    user = User.query.filter_by(username=pro).first()
    posts = Posts.query.filter_by(post_by=pro).order_by(desc(Posts.post_created)).all()
    Total = Posts.query.filter_by(post_by=pro).order_by(Posts.post_created).count()

    if (user):
        image_file = user.profile_picture
        currentuser = User.query.filter_by(username=pro).one()
        return render_template('profile.html',
                                total=Total,
                                posts=posts,
                                admin=current_user.admin,
                                image_file = image_file,
                                name = str(current_user.username),
                                profile = str(currentuser),
                                about=user.about
                                )
    else:
        return render_template('profile.html',
                                total=Total,
                                admin=current_user.admin,
                                image_file = url_for('static',filename='profile_pics/default.png'),
                                name = str(current_user.username),
                                about='This Profile Dosen\'t Exists',
                                profile = 'user dosen\'t exist'
                                )
    

#Link to All Posts
@app.route('/posts')
def posts():
    posts = Posts.query.order_by(desc(Posts.post_created)).all()
    
    return render_template('posts.html',
                            posts=posts
                            )

@app.route('/post/delete/<string:postid>', methods=['GET', 'POST'])
@login_required
def delete(postid):
    post = Posts.query.filter_by(post_id=postid).first()
    if(post.post_by == current_user.username):
        try:
            db.session.delete(post)
            db.session.commit()
            return redirect(url_for('dashboard', pro = current_user.username))
        except:
            return 'An error Occured'
    else:
        return redirect(url_for('dashboard', pro = current_user.username))


@app.route('/post/update/<string:postid>', methods=['GET', 'POST'])
@login_required
def updatepost(postid):
    post = Posts.query.filter_by(post_id=postid).first()
    name = post.post_by
    if (request.method == 'POST'):
        post.post_title = request.form['post_title']
        post.post_body = request.form['post_body']
    
        try:
            db.session.commit()
            return redirect(url_for('dashboard', pro = current_user.username))
        except:
            return redirect(url_for('dashboard', pro = current_user.username))
        
    else:
        return render_template('update-post.html', post=post, name=name , profile = current_user.username)


@app.route('/posts/new', methods=['GET', 'POST'])
@login_required
def addpost():
    if (request.method == 'POST'):
        post_id = secrets.token_urlsafe(8)
        new_post = Posts(post_id = post_id ,post_title = request.form['post_title'],post_by = current_user.username,post_body = request.form['post_body'])
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('dashboard', pro = current_user.username))
        
    else:
        return render_template('add-post.html')

#Link to Posts
@app.route('/post/<string:postid>')
@login_required
def post(postid):
    post = Posts.query.filter_by(post_id=postid).first()
    name = post.post_by
    return render_template('post.html', post=post,name=name, profile = current_user.username)


#Link to Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/livebox', methods=['GET', 'POST'])
def livebox():    
    if (request.method == 'POST'):
        tag = request.form.get("text")
        search = "%{}%".format(tag)
        P_results = Posts.query.filter(Posts.post_body.like(search)).all()
        U_results = User.query.filter(User.username.like(search)).all()
        post_schema = PostSchema(many=True)
        user_schema = UserSchema(many=True)
        post_result = post_schema.dump(P_results)
        user_result = user_schema.dump(U_results)
        return jsonify({'post':post_result,'user':user_result})

@app.route('/search', methods=['GET', 'POST'])
def search():
    if (request.method == 'POST'):
        tag = request.form['search']
        search = "%{}%".format(tag)
        P_results = Posts.query.filter(Posts.post_body.like(search)).all()
        U_results = User.query.filter(User.username.like(search)).all()
        return render_template('search.html',posts=P_results,users=U_results)

        


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
admin.add_view(MyModelView(Posts, db.session))

if __name__ == '__main__':
    app.run()