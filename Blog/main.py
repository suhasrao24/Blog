from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from dotenv import dotenv_values
import os
import smtplib


config = dotenv_values(".env")          # for offline secrets

from_email = config['from_email']
to_email = config['to_email']
password = config['password']
flask_apikey = config['flask_apikey']

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("flask_apikey", flask_apikey)     # online then offline secrets.
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")    # online then offline secrets.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship('Comment', back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship('User', back_populates="comments")

    blogpost_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")


# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            # User already exists
            flash(message="You've already signed up with that email, log in instead!", category='error')
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
        user_data = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(user_data)
        db.session.commit()
        login_user(user_data)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_password = form.password.data
        userdata_in_database = User.query.filter_by(email=user_email).first()
        if userdata_in_database is not None:
            if check_password_hash(pwhash=userdata_in_database.password, password=user_password):
                login_user(userdata_in_database)
                return redirect(url_for('get_all_posts'))
            else:
                flash(message="Wrong Password", category='error')
                return redirect(url_for('login'))
        else:
            flash(message="There is no account in this database with this email-id", category='error')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash(message="You've to register or log in to leave a comment!", category='error')
            return redirect(url_for('login'))
        else:
            comment_data = Comment(
                text=form.comment.data,
                author_id=current_user.id,
                blogpost_id=post_id
            )
            db.session.add(comment_data)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    blogpost_comments = Comment.query.filter_by(blogpost_id=post_id).all()
    requested_post = BlogPost.query.get(post_id)
    if requested_post is None:                          # no post at that post-id.
        return abort(404)
    return render_template("post.html", post=requested_post, comments=blogpost_comments, form=form)


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    try:
        if current_user.id != BlogPost.query.get(int(post_id)).author_id:
            return abort(403)
    except AttributeError:                  # no post at that post-id.
        return abort(404)
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete-post/<int:post_id>")
@login_required
def delete_post(post_id):
    try:
        if current_user.id != BlogPost.query.get(int(post_id)).author_id and current_user.id != 1:
            return abort(403)
    except AttributeError:                  # no post at that post-id.
        return abort(404)
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment/<int:comment_id>")
@login_required
def delete_comment(comment_id):
    try:
        if current_user.id != Comment.query.get(int(comment_id)).author_id and current_user.id != 1:
            return abort(403)
    except AttributeError:                  # no comment at that comment-id.
        return abort(404)
    comment_to_delete = Comment.query.filter_by(id=comment_id).first()
    post_to_return = BlogPost.query.filter_by(id=int(comment_to_delete.blogpost_id)).first()
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_to_return.id))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        data = request.form
        send_email(data["name"], data["email"], data["phone"], data["message"])
        statement = 'Succesfully sent your message'
        return render_template('contact.html', feedback=statement)
    return render_template('contact.html')


def send_email(name, email, phone, message):
    email_message = f"Name: {name}\nEmail: {email}\nPhone: {phone}\nMessage:{message}"
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=from_email, password=password)
        connection.sendmail(from_addr=from_email,
                            to_addrs=to_email,
                            msg=f"Subject:Message from your blog!!\n\n{email_message}")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
