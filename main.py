from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
import os

# --- Start up functions ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro',
                    force_default=False, force_lower=False, use_ssl=False, base_url=None)


database_url = os.environ.get("DATABASE_URL")
# database_url = database_url[:8]+"ql"+database_url[8:]


# --- CONNECT TO DB ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(database_url, "sqlite:///items.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- CONFIGURE TABLES ---

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # posts = relationship("Items", back_populates="author")
    # comments = relationship("Comment", back_populates="comment_author")


class Items(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100))
    description = db.Column(db.String(350))
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)
    img_url = db.Column(db.String(250), nullable=False)
    # comments = relationship("Comment", back_populates="parent_item")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # comment_author = relationship("User", back_populates="comments")

    # item_id=db.Column(db.Integer, db.ForeignKey("blog_items.id"))
    # parent_item = relationship("BlogPost", back_populates="comments")
    # text = db.Column(db.String(250), nullable=False)


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            current_id = current_user.id
        except:
            current_id = 0
        if current_id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_items():
    items = Items.query.all()
    return render_template("index.html", all_items=items, logged_in=current_user.is_authenticated)

# --- Register User ---
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUser()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            regenerate_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=form.email.data,
                name=form.name.data,
                password=regenerate_password
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            flash("You already registered.  Please log in")
            return redirect(url_for('login'))

    return render_template("register.html", form=form)

# --- User management ---
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- User Login ---
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('get_all_items'))
        else:
            flash('User not found / password wrong')
    return render_template("login.html", form=form)


# --- Logout User ---
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_items'))

@app.route('/buy/<int:item_id>', methods=['GET', 'POST'])
def buy_item(item_id):
    return redirect(url_for('get_all_items'))


# --- Show single post ---
@app.route("/post/<int:item_id>", methods=["GET", "POST"])
def show_item(item_id):
    form = CommentForm()
    requested_item = Items.query.get(item_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_item=requested_item
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", item=requested_item, form=form,
                           current_user=current_user, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


# --- Create post ---
@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_item():
    form = CreateItemForm()
    if form.validate_on_submit():
        new_item = Items(
            label=form.label.data,
            description=form.description.data,
            img_url=form.img_url.data,
            quantity=form.quantity.data,
            price=form.price.data
        )
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for("get_all_items"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# --- Edit a post ---
@app.route("/edit-post/<int:item_id>", methods=["GET", "POST"])
@admin_only
def edit_item(item_id):
    post = BlogPost.query.get(item_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_item", item_id=post.id, logged_in=current_user.is_authenticated))

    return render_template("make-post.html", form=edit_form)


# --- Delete post ---
@app.route("/delete/<int:item_id>")
@admin_only
def delete_item(item_id):
    item_to_delete = Items.query.get(item_id)
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_items'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
