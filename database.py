from flask_sqlalchemy import SQLAlchemy
import datetime
from flask_login import login_user, logout_user, UserMixin, AnonymousUserMixin, LoginManager, login_required, \
    current_user

from werkzeug import security
from hashlib import sha512
from cryptography.fernet import Fernet


db = SQLAlchemy()


class Permission(object):
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Users(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer(), primary_key=True,
                   autoincrement=True)
    first_name = db.Column(db.Unicode(64), nullable=False)
    last_name = db.Column(db.Unicode(64), nullable=False)
    email = db.Column(db.Unicode(256), nullable=False, unique=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey("Roles.rid"), default=1)
    subcnitts = db.relationship('Subscriber', lazy='dynamic')

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

    @property
    def password(self):
        raise AttributeError("password is write only")

    @password.setter
    def password(self, password):
        self.password_hash = security.generate_password_hash(password)

    def verify_password(self, password):
        return security.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"[{self.id}] {self.email}"



class AnonymousUser(AnonymousUserMixin):
    def can(self, perm):
        return False

    def is_administrator(self):
        return False


class Roles(db.Model):
    __tablename__ = "Roles"
    rid = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    name = db.Column(db.Unicode(64))
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer, default=0, nullable=False)
    users = db.relationship("Users", backref="role", lazy="dynamic")

    def __init__(self, **kwargs):
        super(Roles, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

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


class SubCnitt(db.Model):
    __tablename__ = "SubCnitts"
    cnitt_id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    name = db.Column(db.String, autoincrement=True, unique=True, nullable=False)
    datetime_created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now())
    subscribers = db.relationship('Subscriber', backref='subs', lazy='dynamic', )

    def create_link_post(self, title, link, user_id):
        post = Post(title=title, content=link, is_link=True, poster=user_id, cnitt_id=self.cnitt_id)
        db.session.add(post)
        db.session.commit()
        return post

    def create_text_post(self, title, content, user_id):
        post = Post(title=title, content=content, is_link=False, poster=user_id, cnitt_id=self.cnitt_id)
        db.session.add(post)
        db.session.commit()
        return post

    def subscribe(self, user_id):
        sub = Subscriber(cnitt_id=self.cnitt_id, user_id=user_id)
        db.session.add(sub)
        db.session.commit()

    def __repr__(self):
        return f"c/{self.name}"


class Subscriber(db.Model):
    #   table_args__ = (SQLAlchemy.PrimaryKeyConstraint('cnitt_id', 'user_id'))
    cnitt_id = db.Column(db.Integer, db.ForeignKey('SubCnitts.cnitt_id'), nullable=False, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"), nullable=False, primary_key=True)


class Post(db.Model):
    __tablename__ = "Posts"
    title = db.Column(db.String, nullable=False)
    pid = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    up_votes = db.Column(db.Integer, nullable=False, default=1)
    down_votes = db.Column(db.Integer, nullable=False, default=0)
    poster = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    cnitt_id = db.Column(db.Integer, db.ForeignKey('SubCnitts.cnitt_id'), nullable=False)
    content = db.Column(db.Text)
    is_link = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        cnitt = SubCnitt.query.filter(SubCnitt.cnitt_id == self.cnitt_id).first()
        votes = self.up_votes - self.down_votes
        return f"{repr(cnitt)} [{votes}] {self.title}"

    def create_comment(self, content, user_id, parent_comment=None):
        user = Users.query.filter(Users.id == user_id).first()
        comment = Comment(post=self.pid, user=user.id, text=content, parent=parent_comment)
        db.session.add(comment)
        db.session.commmit()
        return comment

    def create_comment_chains(self):
        child_tree = {}
        all_comments = Comment.query.filter(Comment.post == self.pid).all()
        base_comments = []
        for c in all_comments:
            child_tree[c.cmnt_id] = []
            if c.parent is None:
                base_comments += [c.cmnt_id]

        for c in all_comments:
            parent_cmnt_id = c.parent
            child_tree[parent_cmnt_id] += [c.cmnt_id]

        return child_tree, base_comments


class Moderator(db.Model):
    uid = db.Column(db.Integer, db.ForeignKey("Users.id"), nullable=False, primary_key=True)
    cnitt_id = db.Column(db.Integer, db.ForeignKey('SubCnitts.cnitt_id'), nullable=False, primary_key=True)


class Comment(db.Model):
    __tablename__ = "Comments"
    cmnt_id = db.Column(db.Integer, nullable=False, primary_key=True, autoincrement=True)
    post = db.Column(db.Integer, db.ForeignKey('Posts.pid'), nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    votes = db.Column(db.Integer, nullable=False, default=0)
    parent = db.Column(db.Integer, db.ForeignKey('Comments.cmnt_id'), nullable=True)




def subscribe(app, uid, cnitt_id):
    with app.app_context():
        sub = Subscriber(cnitt_id=cnitt_id, user_id=uid)
        db.session.add(sub)
        db.session.commit()


