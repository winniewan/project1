from flask import Blueprint

from database import Post

post_page = Blueprint('post_page', __name__, template_folder='templates')


@post_page.route("/c/<string:cnitt_name>/comments/<int:post_id>", defaults={'sort_type': 'Hot'})
@post_page.route("/c/<string:cnitt_name>/comments/<int:post_id>/<string:sort_type>")
def comments_for_post(cnitt_name, post_id, sort_type):
    return f"Here will be info from the post {repr(Post.query.filter(Post.pid == post_id).first())} {cnitt_name}\
     with sorting of {sort_type}", 200

