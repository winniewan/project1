import json
import os
from flask import Flask, render_template, abort, redirect, request, url_for, flash
from flask_login import login_user, logout_user, UserMixin, AnonymousUserMixin, LoginManager, login_required, \
    current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import wtforms as wtf
import wtforms.validators as valid
from functools import wraps
import base64
from werkzeug import security
from hashlib import sha512
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


appdir = os.path.abspath(os.path.dirname("Gal's_webprogramming_project.ipynb"))

# configure app’s database access
app.config["SQLALCHEMY_DATABASE_URI"] = \
    f"sqlite:///{os.path.join(appdir, 'library.db')}"
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


def permission_required(perm):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(perm):
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def admin_required(f):
    return permission_required(Permission.ADMIN)(f)


#
##
###Database classes
##
#

class Users(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer(), primary_key=True,
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

    @property
    def password(self):
        raise AttributeError("password is write only")

    @password.setter
    def password(self, password):
        self.password_hash = security.generate_password_hash(password)

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

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

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


#
##
###WTForm classes
##
#

class New_User_Form(FlaskForm):
    first_name = wtf.StringField("first_name", validators=[valid.DataRequired()])
    last_name = wtf.StringField("last_name", validators=[valid.DataRequired()])
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
##
#

@app.route('/')
def index():
    return render_template('homePage.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is not None and Users.verify_password(user, password=form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("index")
            return redirect(next)
        flash("Invalid Username or password.")
    return render_template("login.html", form=form)


@app.route("/admin")
@login_required
@admin_required
def for_admins_only():
    return "Congratulations on Administrator Privileges!"


@app.route("/moderate")
@login_required
@permission_required(Permission.MODERATE)
def for_moderators_only():
    return "Congratulations on Moderator Privileges!"


@app.route("/secret")
@login_required
def secret():
    return "Congratulations on being logged in!"


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for("index"))


@app.route("/login_logout")
def login_logout():
    return render_template("login_logout.html"), 200


@app.route("/raw/<int:uid>")
def raw(uid):
    return str(users[str(uid)])


@app.route("/add_user", methods=["GET", "POST"])
def add_user():
    User = None
    fname, lname, email, password = None, None, None, None
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
        user = Users(first_name=fname, last_name=lname, email=email, password=password)
        db.session.add_all([user])
        db.session.commit()
        next = request.args.get("next")
        if next is None or not next.startswith("/"):
            next = url_for("index")
        return redirect(next)
    return render_template("add_user.html", form=form)


@app.route("/users/<int:uid>")
def users(uid):
    user = Users.query.filter_by(id=uid).first()
    # print(help(user))
    if (user != None):
        return render_template("forum.html", user=user), 200
    else:
        print("oops")
        abort(404)


def initialize_app():
    user = Users(first_name="Gal", last_name="Cherki", email="gal.cherki@hotmail.com", password="math")
    user.can(1)
    db.session.add_all([user])
    db.session.commit()


if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"))
    initialize_app()