
import os
from functools import wraps

import wtforms as wtf
import wtforms.validators as valid
from flask import Flask, render_template, abort, redirect, request, url_for, flash
from flask_login import login_user, logout_user, LoginManager, login_required, \
    current_user
from flask_wtf import FlaskForm
from sqlalchemy import update
from database import *
from werkzeug.datastructures import MultiDict

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



#
##
### permission requirements
##
#

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
###WTForm classes
##
#

class New_User_Form(FlaskForm):
    username = wtf.StringField("username", validators=[valid.DataRequired()])
    first_name = wtf.StringField("first_name", validators=[valid.DataRequired()])
    last_name = wtf.StringField("last_name", validators=[valid.DataRequired()])
    email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Email()])
    password = wtf.PasswordField("Password", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("Submit")
    comments = wtf.TextAreaField("Comment", validators=[])

class Edit_User_Form(FlaskForm):
    first_name = wtf.StringField("first_name", validators=[valid.DataRequired()])
    last_name = wtf.StringField("last_name", validators=[valid.DataRequired()])
    # email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Email()])
    # bio = wtf.PasswordField("Bio", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("Submit")

class LoginForm(FlaskForm):
    email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Length(1, 64), valid.Email()])
    password = wtf.PasswordField("Password", validators=[valid.DataRequired()])
    remember_me = wtf.BooleanField("Keep me logged in")
    submit = wtf.SubmitField("Log In")

class SearchBar(FlaskForm):
    wanted = wtf.StringField("wanted", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("search")
    
class RoleForm(FlaskForm):
    email = wtf.StringField("Email", validators=[valid.DataRequired(), valid.Length(1, 64), valid.Email()])
    role_name = wtf.StringField("Role", validators=[valid.DataRequired()])
    submit = wtf.SubmitField("change_role")

class TextPostForm(FlaskForm):
    title = wtf.StringField("Title", validators= [valid.DataRequired(), valid.Length(1, 64)])
    content = wtf.TextAreaField("Content", validators= [valid.DataRequired()])
    submit = wtf.SubmitField("Make Post")

class LinkPostForm(FlaskForm):
    title = wtf.StringField("Title", validators= [valid.DataRequired(), valid.Length(1, 64)])
    content = wtf.TextAreaField("Link", validators= [valid.DataRequired(), valid.URL()])
    submit = wtf.SubmitField("Make Post")

class CommentForm(FlaskForm):
    content = wtf.TextAreaField("Write Comment Here", validators = [valid.DataRequired()])
    submit = wtf.SubmitField("Make Post")


# clearing the database
with app.app_context():
    db.drop_all()
    db.create_all()


#
##
### app route functions
##
#

@app.route('/', methods=["GET", "POST"])
def index():
    searchform = SearchBar()
    posts = SubCnitt.get("Front").posts()
    subscribed = SubCnitt.get_top_n_subscribed(8)
    if searchform.validate_on_submit():
        next = search(searchform.wanted.data)
        return redirect(next)
    return render_template('home.html', posts=posts, cnitt_name="Front", top_cnitts=subscribed,users=Users,searchform=searchform)

def search(wanted):
    user = Users.query.filter_by(username=wanted).first()
    if user is not None:
        return url_for("users",uid=user.id)
    scene = SubCnitt.query.filter_by(name=wanted).first()
    if scene is not None:
        return url_for("show_sub_cnitt", cnitt_name = scene.name, sort_type = 'Hot')
    post = Post.query.filter_by(title=wanted).first()
    if post is not None:
        return url_for("comments_for_post",cnitt_name=post.cnitt_name,post_id=post.pid)
    return url_for("index")

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/editProfile/<int:uid>', methods =["GET", "POST"])
@login_required
def editProfile(uid):
    user = Users.query.filter_by(id=uid).first()
    posts = Post.query.filter_by(poster=uid).all()
    if request.method == 'GET':
        form = Edit_User_Form(formdata=MultiDict({'first_name': current_user.first_name, 'last_name': current_user.last_name}))
    else :
        form = Edit_User_Form()
    # form.email_name.data = current_user.first_name
    # form.bio_name.data = current_user.first_name
    if form.validate_on_submit():
        # username = form.username.data
        # form.username.data = None
        fname = form.first_name.data
        form.first_name.data = None
        lname = form.last_name.data
        form.last_name.data = None
        # email = form.email.data
        # form.email.data = None
        # password = form.password.data
        # form.password.data = None
        #if Users.query.filter_by(email=email).first() is None and Users.query.filter_by(username=username).first() is None:
        user.first_name = fname
        user.last_name = lname
        db.session.commit()
        return redirect(url_for("users", uid=current_user.id))
    if (user != None and posts != None):
        return render_template("editProfile.html", uid=uid, user=user, posts=posts, form=form), 200
    elif (user != None):
        return render_template("editProfile.html", uid=uid, user=user, form=form), 200
    else:
        print("oops")
        abort(404)

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

@app.route("/add_user", methods=["GET", "POST"])
def add_user():
    form = New_User_Form()
    if form.validate_on_submit():
        username = form.username.data
        form.username.data = None
        fname = form.first_name.data
        form.first_name.data = None
        lname = form.last_name.data
        form.last_name.data = None
        email = form.email.data
        form.email.data = None
        password = form.password.data
        form.password.data = None
        if Users.query.filter_by(email=email).first() is None and Users.query.filter_by(username=username).first() is None:
            user = Users(first_name=fname, last_name=lname, email=email, password=password,username=username)
            db.session.add_all([user])
            db.session.commit()
            SubCnitt.add_required_subscriptions()
            next = request.args.get("next")
            if next is None or not next.startswith("/"):
                next = url_for("index")
            return redirect(next)
        else:
             flash("user with this email or username already exists")
    return render_template("add_user.html", form=form)


@app.route("/users/<int:uid>")
@login_required
def users(uid):
    user = Users.query.filter_by(id=uid).first()
    posts = Post.query.filter_by(poster=uid).all()
    # print(help(user))
    if (user != None and posts != None):
        return render_template("profile.html", user=user, posts = posts), 200
    elif (user != None):
        return render_template("profile.html", user=user), 200
    else:
        print("oops")
        abort(404)

# @app.route("/make_text_post", methods=["GET","POST"])
# def make_text_post(cnitt_name):
#     return render_template ("forum.html"), 200

@app.route("/c/<string:cnitt_name>/mtp", methods = ["GET", "POST"])
@login_required
def mtp(cnitt_name):
    title = None
    cnitt = SubCnitt.get(cnitt_name)
    form = TextPostForm()
    if form.validate_on_submit():
        title = form.title.data
        form.title.data = None
        content = form.content.data
        form.content.data = None
        post = cnitt.create_text_post(title, content, current_user.id)
        next = request.args.get("next")
        if next is None or not next.startswith("/"):
            next = url_for("show_sub_cnitt", cnitt_name = cnitt_name, sort_type = 'Hot')
        return redirect(next)
    return render_template ("text_post_submission.html", form = form), 200

@app.route("/c/<string:cnitt_name>/mlp", methods = ["GET", "POST"])
@login_required
def mlp(cnitt_name):
    title = None
    cnitt = SubCnitt.get(cnitt_name)
    form = LinkPostForm()
    if form.validate_on_submit():
        title = form.title.data
        form.title.data = None
        content = form.content.data
        form.content.data = None
        post = cnitt.create_link_post(title, content, current_user.id)
        next = request.args.get("next")
        if next is None or not next.startswith("/"):
            next = url_for("show_sub_cnitt", cnitt_name = cnitt_name, sort_type = 'Hot')
        return redirect(next)
    return render_template ("link_post_submission.html", form = form), 200


@app.route("/c", methods=["GET"])
@app.route("/c/", defaults={'cnitt_name': 'Front'}, methods=["GET"])
@app.route("/c/<string:cnitt_name>", methods=["GET"])
@app.route("/c/<string:cnitt_name>/<string:sort_type>", methods=["GET"])
def show_sub_cnitt(cnitt_name="Front", sort_type='Hot'):
    cnitt = SubCnitt.get(cnitt_name)
    if cnitt is None:
        return redirect(url_for("index")), 404

    if not current_user.is_authenticated:
        id = None
    else:
        id = current_user.id

    num_posts = request.args.get("count")
    if num_posts is not None:
        num_posts = int(num_posts)
    after = request.args.get("after")
    if after is not None:
        after = int(after)

    if num_posts is None and after is None:
        posts = cnitt.posts(sort_type=sort_type, user_id=id)
    elif num_posts is None:
        posts = cnitt.posts(sort_type=sort_type, start=after, user_id=id)
    elif after is None:
        posts = cnitt.posts(sort_type=sort_type, quantity=num_posts, user_id=id)
    else:
        posts = cnitt.posts(sort_type=sort_type, quantity=num_posts, start=after, user_id=id)
    # SHOW POSTS HERE

    return render_template("forum.html", posts=posts, cnitt_name=cnitt_name, cnitt=cnitt, after=after,users=Users), 200


@app.route("/c/<string:cnitt_name>/comments/<int:post_id>",  methods = ["GET", "POST"], defaults={'sort_type': 'Hot'})
@app.route("/c/<string:cnitt_name>/comments/<int:post_id>/<string:sort_type>",  methods = ["GET", "POST"])
def comments_for_post(cnitt_name, post_id, sort_type):
    post = Post.query.filter_by(pid = post_id).first()
    comments = Comment.query.filter_by(post = post_id).all()
    if post != None:
        return render_template("post.html", post = post,cnitt_name = cnitt_name, comments = comments)
    else:
        print("oops")
        abort(404)


@app.route("/subscribe/<string:cnitt>")
@login_required
def subscribe(cnitt):
    get = SubCnitt.get(cnitt)
    if get is None:
        redirect("/")
    elif current_user is not None:
        get.subscribe(current_user.id)
    return redirect("/c/" + cnitt)


@app.route("/unsubscribe/<string:cnitt>")
@login_required
def unsubscribe(cnitt):
    get = SubCnitt.get(cnitt)
    if get is None:
        redirect("/")
    elif current_user is not None:
        get.unsubscribe(current_user.id)
    return redirect("/c/" + cnitt)



@app.route("/makeComment/<string:cnitt_name>/<int:post_id>",  methods = ["GET", "POST"])
def makeComment(cnitt_name, post_id):
    post = Post.query.filter_by(pid = post_id).first()
    user_id = current_user.id
    form = CommentForm()
    if form.validate_on_submit():
        content = form.content.data
        form.content.data = None
        post.create_comment(content, user_id)
        next = request.args.get("next")
        if next is None or not next.startswith("/"):
            next = url_for("comments_for_post", cnitt_name = cnitt_name, post_id = post_id)
        return redirect(next)
    return render_template ("commentForm.html", form = form), 200


def initialize_app():
    newt = Roles(name="newt", default=True, permissions=0)
    follow = Roles(name="follow", permissions=1)
    comment = Roles(name="comment", permissions=3)
    write = Roles(name="write", permissions=7)
    mod = Roles(name="moderator", permissions=15)
    admin = Roles(name="admin", permissions=31)
    gal_user = Users(username = "gcherki",first_name="Gal", last_name="Cherki", email="gal.cherki@hotmail.com", password="math", role_id=6)
    josh_user = Users(username = "jradin",first_name="Josh", last_name="Radin", email="jradin16@gmail.com", password="helloworld",role_id=6)
    matt_user = Users(username = "mleone",first_name="Matthew", last_name="Leone", email="mleone10@u.rochester.edu", password="scopophobic",role_id=6)
    all_cnitt = SubCnitt(name="All", required_subscription=True)
    front_cnitt = SubCnitt(name="Front", required_subscription=True)
    pictures = SubCnitt(name="pics")
    rochester = SubCnitt(name="roch")
    leibenning = SubCnitt(name="leibenning")
    funny = SubCnitt(name="funny")
    beauty = SubCnitt(name="beauty")
    memes = SubCnitt(name="memes")
    pokemon = SubCnitt(name="pokemon")
    games = SubCnitt(name="games")
    life = SubCnitt(name="life")
    with app.app_context():
        db.session.add_all([newt, follow, comment, write, mod, admin])
        db.session.add_all([gal_user, josh_user, matt_user])
        db.session.add_all([all_cnitt, front_cnitt, pictures, rochester, leibenning, funny])
        db.session.add_all([beauty, memes, pokemon, games, life])
        db.session.commit()
        user = db.session.query(Users).filter(Users.email == "jradin16@gmail.com").first()
        #all_cnitt.subscribe(user.id)


        SubCnitt.add_required_subscriptions()
        all_cnitt.create_link_post("TEST POST PLEASE IGNORE 1", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", user.id)
        all_cnitt.create_text_post("TEST POST PLEASE IGNORE 2", "hello world, again", user.id)


def get_the_all_cnitt():
    with app.app_context():
        return db.session.query(SubCnitt).filter(SubCnitt.name == "All").first()


def get_subscribed():
    if current_user is not None:
        return SubCnitt.query.join(Subscriber.cnitt_id).filter(Subscriber.user_id == current_user.id)


initialize_app()


def run():
    app.run(ssl_context=("cert.pem", "key.pem"))

if __name__ == '__main__':
    run()
