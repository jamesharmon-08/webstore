from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField, FloatField
from wtforms.validators import DataRequired, URL, InputRequired
from flask_ckeditor import CKEditorField


# #WTForm
class CreateItemForm(FlaskForm):
    label = StringField("Item Label", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()])
    img_url = StringField("Item Image", validators=[DataRequired(), URL()])
    quantity = IntegerField("Quantity", validators=[InputRequired()])
    price = FloatField("Unit Price", validators=[InputRequired()])
    submit = SubmitField("Submit Post")


class RegisterUser(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign up")


class LoginUser(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
