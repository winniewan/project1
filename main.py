<<<<<<< HEAD
import json
import os
from flask import Flask, render_template, abort,redirect,request,url_for,flash
from flask_login import login_user,logout_user, UserMixin,AnonymousUserMixin, LoginManager, login_required, current_user
=======
import os
from flask import Flask, render_template, abort, redirect, request, url_for, flash
from flask_login import login_user, logout_user, UserMixin, AnonymousUserMixin, LoginManager, login_required, \
    current_user
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import wtforms as wtf
import wtforms.validators as valid
from functools import wraps
import base64
from werkzeug import security
from hashlib import sha512
<<<<<<< HEAD
from cryptography.fernet import Fernet
#google oauth
=======

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e

app = Flask(__name__)
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

<<<<<<< HEAD
=======

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
appdir = os.path.abspath(os.path.dirname("Gal's_webprogramming_project.ipynb"))

# configure app’s database access
app.config["SQLALCHEMY_DATABASE_URI"] = \
<<<<<<< HEAD
	f"sqlite:///{os.path.join(appdir, 'library.db')}"
=======
    f"sqlite:///{os.path.join(appdir, 'library.db')}"
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# initialize the SQLAlchemy database adaptor
db = SQLAlchemy(app)


#
##
### permission requirements
##
#

class Permission(object):
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16

<<<<<<< HEAD
=======

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
def permission_required(perm):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(perm):
                abort(403)
            return f(*args, **kwargs)
<<<<<<< HEAD
        return decorated_function
    return decorator
    
def admin_required(f):
    return permission_required(Permission.ADMIN)(f)

=======

        return decorated_function

    return decorator


def admin_required(f):
    return permission_required(Permission.ADMIN)(f)


>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
#
##
###Database classes
##
#

class Users(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer(), primary_key=True,
<<<<<<< HEAD
    autoincrement=True)
    first_name = db.Column(db.Unicode(64), nullable=False)
    last_name = db.Column(db.Unicode(64), nullable=False)
    email = db.Column(db.Unicode(256), nullable=False,unique=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey("Roles.rid"), default=1)
    
    def change_user_role(self, new_role):
        role = Roles.query.filter_by(rid=new_role).first()
        print(role)
        print("hello")
        if role is not None:
            self.role_id = new_role
            db.session.add(self)
            db.session.commit()
        else:
            print("there was an error " + self.first_name + str(new_role))
    
    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)
    
    def is_administrator(self):
        return self.can(Permission.ADMIN)
    
=======
                   autoincrement=True)
    first_name = db.Column(db.Unicode(64), nullable=False)
    last_name = db.Column(db.Unicode(64), nullable=False)
    email = db.Column(db.Unicode(256), nullable=False, unique=True)
    password = db.Column(db.Unicode(256), nullable=False)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey("Roles.id"))

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
    @property
    def password(self):
        raise AttributeError("password is write only")

    @password.setter
    def password(self, password):
        self.password_hash = security.generate_password_hash(password)
<<<<<<< HEAD
    def verify_password(self, password):
        return security.check_password_hash(self.password_hash, password)
    
class AnonymousUser(AnonymousUserMixin):
    def can(self, perm):
        return False
    def is_administrator(self):
        return False

class Comments(db.Model):
    __tablename__ = "Comments"
    id = db.Column(db.Integer(), primary_key=True,
    autoincrement=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('Users.id'))
    comment = db.Column(db.Unicode(256), nullable=False)

class Roles(db.Model):
    __tablename__ = "Roles"
    rid = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    name = db.Column(db.Unicode(64))
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer,default=0,nullable=False)
    users = db.relationship("Users", backref="role", lazy="dynamic")
    
=======

    def verify_password(self, password):
        return security.check_password_hash(self.password_hash, password)


class AnonymousUser(AnonymousUserMixin):
    def can(self, perm):
        return False

    def is_administrator(self):
        return False


class Comments(db.Model):
    __tablename__ = "Comments"
    id = db.Column(db.Integer(), primary_key=True,
                   autoincrement=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('Users.id'))
    comment = db.Column(db.Unicode(256), nullable=False)


class Roles(db.Model):
    __tablename__ = "Roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship("Users", backref="role", lazy="dynamic")

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
    def __init__(self, **kwargs):
        super(Roles, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0
<<<<<<< HEAD
            
    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm
    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm
    def reset_permissions(self):
        self.permissions = 0
    def has_permission(self, perm):
            return self.permissions & perm == perm
    
=======

    def add_permission(self, perm):
        if not self.has_permissions(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm


>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
#
##
###WTForm classes
##
#

class New_User_Form(FlaskForm):
    first_name = wtf.StringField("first_name", validators=[valid.DataRequired()])
    last_name = wtf.StringField("last_name", validators=[valid.DataRequired()])
<<<<<<< HEAD
    email = wtf.StringField("Email",validators=[valid.DataRequired(), valid.Email()])
    password = wtf.PasswordField("Password",validators=[valid.DataRequired()])
    submit = wtf.SubmitField("Submit")
    comments = wtf.TextAreaField("Comment", validators=[])

class LoginForm(FlaskForm):
    email = wtf.StringField("Email", validators=[valid.DataRequired(),valid.Length(1,64), valid.Email()])
    password = wtf.PasswordField("Password", validators=[valid.DataRequired()])
    remember_me = wtf.BooleanField("Keep me logged in")
    submit = wtf.SubmitField("Log In")
    
class RoleForm(FlaskForm):
    email = wtf.StringField("Email", validators=[valid.DataRequired(),valid.Length(1,64), valid.Email()])
    role_name = wtf.StringField("Role", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("change_role")
        
#clearing the database
db.drop_all()
db.create_all()

#
##
###app route functions    
=======
    email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Email()])
    password = wtf.PasswordField("Password", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("Submit")
    comments = wtf.TextAreaField("Comment", validators=[])


class LoginForm(FlaskForm):
    email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Length(1, 64), valid.Email()])
    password = wtf.PasswordField("Password", validators=[valid.DataRequired()])
    remember_me = wtf.BooleanField("Keep me logged in")
    submit = wtf.SubmitField("Log In")


# clearing the database
db.drop_all()
db.create_all()


#
##
###app route functions
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
##
#

@app.route('/')
def index():
<<<<<<< HEAD
	return render_template('homePage.html')

@app.route("/login", methods=["GET","POST"])
=======
    return render_template('homePage.html')


@app.route("/login", methods=["GET", "POST"])
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
<<<<<<< HEAD
        if user is not None and Users.verify_password(user,password=form.password.data):
=======
        if user is not None and Users.verify_password(user, password=form.password.data):
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("index")
            return redirect(next)
        flash("Invalid Username or password.")
    return render_template("login.html", form=form)


<<<<<<< HEAD
@app.route("/admin", methods=["GET","POST"])
@login_required
#@admin_required
@permission_required(Permission.ADMIN)
def for_admins_only():
    role_form = RoleForm()
    if role_form.validate_on_submit():
        user = Users.query.filter_by(email=role_form.email.data).first()
        role = Roles.query.filter_by(name=role_form.role_name.data).first()
        if user is not None and role is not None:
            user.change_user_role(role.rid)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("index")
            return redirect(next)
        flash("Invalid Username or role")
        print("Invalid Username or role")
    return render_template("admin.html", form=role_form)

=======
@app.route("/admin")
@login_required
@admin_required
def for_admins_only():
    return "Congratulations on Administrator Privileges!"
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e


@app.route("/moderate")
@login_required
@permission_required(Permission.MODERATE)
def for_moderators_only():
    return "Congratulations on Moderator Privileges!"

<<<<<<< HEAD
=======

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
@app.route("/secret")
@login_required
def secret():
    return "Congratulations on being logged in!"

<<<<<<< HEAD
=======

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for("index"))

<<<<<<< HEAD
=======

>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
@app.route("/login_logout")
def login_logout():
    return render_template("login_logout.html"), 200

<<<<<<< HEAD
@app.route("/raw/<int:uid>")
def raw(uid):
	return str(users[str(uid)])

@app.route("/add_user", methods=["GET","POST"])
def add_user():
    User = None
    fname,lname,email,password = None, None, None, None
=======

@app.route("/raw/<int:uid>")
def raw(uid):
    return str(users[str(uid)])


@app.route("/add_user", methods=["GET", "POST"])
def add_user():
    User = None
    fname, lname, email, password = None, None, None, None
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
    form = New_User_Form()
    if form.validate_on_submit():
        fname = form.first_name.data
        form.first_name.data = None
        lname = form.last_name.data
        form.last_name.data = None
        email = form.email.data
        form.email.data = None
        password = form.password.data
        form.password.data = None
<<<<<<< HEAD
        user = Users(first_name=fname, last_name=lname, email=email,password=password)
=======
        user = Users(first_name=fname, last_name=lname, email=email, password=password)
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
        db.session.add_all([user])
        db.session.commit()
        next = request.args.get("next")
        if next is None or not next.startswith("/"):
            next = url_for("index")
        return redirect(next)
    return render_template("add_user.html", form=form)

<<<<<<< HEAD
@app.route("/users/<int:uid>")
def users(uid):
    user = Users.query.filter_by(id=uid).first()
    #print(help(user))
    if (user != None):
        return render_template("forum.html",user=user), 200
=======

@app.route("/profile/<int:uid>", methods=["GET"])
def profile(uid):
    user = Users.query.filter_by(id=uid).first()
    return render_template('profile.html')

@app.route("/users/<int:uid>")
def users(uid):
    user = Users.query.filter_by(id=uid).first()
    # print(help(user))
    if (user != None):
        return render_template("forum.html", user=user), 200
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
    else:
        print("oops")
        abort(404)

<<<<<<< HEAD
@app.before_first_request
def intitialize_app():
    newt = Roles(name="newt",default=True,permissions=0)
    follow = Roles(name="follow",permissions=1)
    comment = Roles(name="comment",permissions=3)
    write = Roles(name="write",permissions=7)
    mod = Roles(name="moderator",permissions=15)
    admin = Roles(name="admin",permissions=31)
    db.session.add_all([newt,follow,comment,write,mod,admin])
    gal_user = Users(first_name="Gal", last_name="Cherki", email="gal.cherki@hotmail.com",password="math",role_id=6)
    db.session.add_all([gal_user])
    db.session.commit()
    
    
        
if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"))
=======

def initialize_app():
    user = Users(first_name="Gal", last_name="Cherki", email="gal.cherki@hotmail.com", password="math")
    user.can(1)
    db.session.add_all([user])
    db.session.commit()


if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"))
    initialize_app()
>>>>>>> 56607c1b78ce8014ddabe2b598d77156f4bcf77e
