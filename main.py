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
from database import db

# google oauth

app = Flask(__name__)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
appdir = os.path.abspath(os.path.dirname("Gal's_webprogramming_project.ipynb"))
app.config["SECRET_KEY"] = "oEHYBreJ2QSefBdUhD19PkxC"
# configure app’s database access
app.config["SQLALCHEMY_DATABASE_URI"] = \
    f"sqlite:///{os.path.join(appdir, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app=app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# initialize the SQLAlchemy database adaptor


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


class RoleForm(FlaskForm):
    email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Length(1, 64), valid.Email()])
    role_name = wtf.StringField("Role", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("change_role")


# clearing the database
with app.app_context():
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


@app.route("/admin", methods=["GET", "POST"])
@login_required
# @admin_required
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


def intitialize_app():
    newt = Roles(name="newt", default=True, permissions=0)
    follow = Roles(name="follow", permissions=1)
    comment = Roles(name="comment", permissions=3)
    write = Roles(name="write", permissions=7)
    mod = Roles(name="moderator", permissions=15)
    admin = Roles(name="admin", permissions=31)
    with app.app_context():
        db.session.add_all([newt, follow, comment, write, mod, admin])
        gal_user = Users(first_name="Gal", last_name="Cherki", email="gal.cherki@hotmail.com", password="math", role_id=6)

        db.session.add_all([gal_user])
        db.session.commit()


if __name__ == "__main__":
    intitialize_app()
    app.run(ssl_context=("cert.pem", "key.pem"))
