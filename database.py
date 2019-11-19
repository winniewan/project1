import datetime

from flask_login import UserMixin, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import PrimaryKeyConstraint
from werkzeug import security

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
    name = db.column_property(first_name + ' ' + last_name)
    email = db.Column(db.Unicode(256), nullable=False, unique=True)
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

    def get_subscriptions(self):
        return SubCnitt.query.join(Subscriber).filter(Subscriber.user_id == self.id).all()

    @property
    def subscriptions(self):
        return self.get_subscriptions()

    @property
    def password(self):
        raise AttributeError("password is write only")

    @password.setter
    def password(self, password):
        self.password_hash = security.generate_password_hash(password)

    def verify_password(self, password):
        return security.check_password_hash(self.password_hash, password)

    def up_vote_post(self, pid):
        Post.query.filter(Post.pid == pid).first().up_vote(self.id)

    def down_vote_post(self, pid):
        Post.query.filter(Post.pid == pid).first().down_vote(self.id)

    '''
    def __repr__(self):
        return f"[{self.id}] {self.email}"
    '''


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
    name = db.Column(db.String(30), autoincrement=True, unique=True, nullable=False)
    datetime_created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    required_subscription = db.Column(db.Boolean, nullable=False, default=False)
    subscribers = db.relationship('Subscriber', backref='subs', lazy='dynamic')

    def create_link_post(self, title, link, user_id):
        post = Post(title=title, content=link, is_link=True, poster=user_id, cnitt_id=self.cnitt_id)
        db.session.add(post)
        db.session.commit()
        post.up_vote(user_id)
        return post

    def create_text_post(self, title, content, user_id):
        post = Post(title=title, content=content, is_link=False, poster=user_id, cnitt_id=self.cnitt_id)
        db.session.add(post)
        db.session.commit()
        post.up_vote(user_id)
        return post

    def subscribe(self, user_id):
        if Subscriber.query.filter_by(cnitt_id=self.cnitt_id, user_id=user_id).first() is None:
            sub = Subscriber(cnitt_id=self.cnitt_id, user_id=user_id)
            db.session.add(sub)
            db.session.commit()

    @staticmethod
    def get_subscribed(user_id):
        return SubCnitt.query.join(Subscriber).filter(Subscriber.user_id == user_id).all()

    def posts(self, sort_type='Hot', start=0, quantity=25, user_id=None):

        output = []
        if self.name == "All" or (self.name == "Front" and user_id is None):
            query_filter = Post.query
        elif self.name == "Front":
            query_filter = Post.query.select_from(Subscriber).join(Post, Post.cnitt_id == Subscriber.cnitt_id).filter(Subscriber.user_id == user_id)
        else:
            query_filter = Post.query.filter_by(cnitt_id=self.cnitt_id)

        if sort_type == 'Hot':
            all_posts = query_filter.order_by(Post.post_hotness_rating.desc())
        elif sort_type == 'New':
            all_posts = query_filter.order_by(Post.created.desc())
        elif sort_type == 'Top':
            all_posts = query_filter.order_by(Post.net_votes.desc())
        else:
            return []

        output = all_posts.offset(start).limit(quantity).all()
        return output

    def __repr__(self):
        return f"c/{self.name}"

    @staticmethod
    def add_required_subscriptions(user_id=None):
        if user_id is None:
            users = Users.query.all()
        else:
            users = Users.query.filter_by(user_id=user_id).all()

        required_subscriptions = SubCnitt.query.filter_by(required_subscription=True).all()
        for u in users:
            for r in required_subscriptions:
                r.subscribe(u.id)

    @staticmethod
    def get(name="Front"):
        return SubCnitt.query.filter_by(name=name).first()


class Subscriber(db.Model):
    __table_args__ = (PrimaryKeyConstraint('cnitt_id', 'user_id'),)
    cnitt_id = db.Column(db.Integer, db.ForeignKey('SubCnitts.cnitt_id'), nullable=False, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"), nullable=False, primary_key=True)


class Vote(db.Model):
    vote_num = db.Column(db.Integer, nullable=False, primary_key=True, autoincrement=True)
    post_id = db.Column(db.Integer, db.ForeignKey('Posts.pid'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"), nullable=False)
    is_up_vote = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"{repr(Users.query.filter(Users.id == self.user_id).first())} voted on {repr(Post.query.filter(Post.pid == self.post_id).first())} "


class Post(db.Model):
    __tablename__ = "Posts"
    title = db.Column(db.String, nullable=False)
    pid = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    up_votes = db.Column(db.Integer, nullable=False, default=0)
    down_votes = db.Column(db.Integer, nullable=False, default=0)
    net_votes = db.column_property(up_votes - down_votes)
    controversial_rating = db.column_property(down_votes * (up_votes + down_votes))
    poster = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    cnitt_id = db.Column(db.Integer, db.ForeignKey('SubCnitts.cnitt_id'), nullable=False)
    content = db.Column(db.Text)
    is_link = db.Column(db.Boolean, nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    hotness_rating = db.Query(net_votes / (datetime.datetime.now() - created))
    modified = db.Column(db.DateTime, nullable=True, default=None, onupdate=datetime.datetime.now)

    def __repr__(self):
        cnitt = SubCnitt.query.filter(SubCnitt.cnitt_id == self.cnitt_id).first()
        votes = self.up_votes - self.down_votes
        user = Users.query.filter_by(id=self.poster).first().name
        return f"{repr(cnitt)}.{self.pid} [{votes}] {self.title} - {user}"

    def up_vote(self, user_id):
        prev_vote = Vote.query.filter(self.pid == Vote.post_id).filter(Vote.user_id == user_id).first()
        if prev_vote is None:
            vote = Vote(post_id=self.pid, user_id=user_id, is_up_vote=True)
            self.up_votes += 1
            db.session.add(vote)
            db.session.commit()
        elif not prev_vote.is_up_vote:
            prev_vote.is_up_vote = True
            self.up_votes += 1
            self.down_votes -= 1
            db.session.commit()

    def down_vote(self, user_id):
        prev_vote = Vote.query.filter(self.pid == Vote.post_id).filter(Vote.user_id == user_id).first()
        if prev_vote is None:
            vote = Vote(post_id=self.pid, user_id=user_id, is_up_vote=False)
            self.down_votes += 1
            db.session.add(vote)
            db.session.commit()
        elif prev_vote.is_up_vote:
            prev_vote.is_up_vote = False
            self.up_votes -= 1
            self.down_votes += 1
            db.session.commit()

    def post_hotness_rating(self):
        return self.net_votes / ((datetime.datetime.now() - self.created).seconds.real + 1)

    def create_comment(self, content, user_id, parent_comment=None):
        user = Users.query.filter(Users.id == user_id).first()
        comment = Comment(post=self.pid, user=user.id, text=content, parent=parent_comment)
        db.session.add(comment)
        db.session.commit()
        return comment

    @property
    def cnitt_name(self):
        return SubCnitt.query.filter_by(cnitt_id=self.cnitt_id).first().name

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
            if parent_cmnt_id is not None:
                child_tree[parent_cmnt_id] += [c.cmnt_id]

        return child_tree, base_comments


class Moderator(db.Model):
    mod_number = db.Column(db.Integer, nullable=False, primary_key=True, autoincrement=True)
    uid = db.Column(db.Integer, db.ForeignKey("Users.id"), nullable=False)
    cnitt_id = db.Column(db.Integer, db.ForeignKey('SubCnitts.cnitt_id'), nullable=False)


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



