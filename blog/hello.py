from flask import Flask
from flask import render_template, flash, url_for, request, redirect, session
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, PasswordField, SubmitField, TextAreaField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime

#create falsk instance
app = Flask(__name__)
#password hash
bcrypt = Bcrypt(app)
#database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#secretkey
app.config['SECRET_KEY'] = 'thisisasecretkeybygflaskform'
#init db
db = SQLAlchemy(app)
migrate = Migrate(app, db)

#create models
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(256), nullable=False)
    password_hash = db.Column(db.String(256))
    created = db.Column(db.DateTime, default=db.func.now())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class Posts(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(128))
        slug = db.Column(db.String(128))
        content = db.Column(db.Text)
        author = db.Column(db.String(128), nullable=False)
        date_posted = db.Column(db.DateTime, default=db.func.now())

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)


#create a form class
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("E-Mail", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), EqualTo('password_confirm', message='Password Must Match!')])
    password_confirm = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    email = StringField("E-Mail", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    slug = StringField("Slug", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create routes
@app.route('/')
def index():
    posts = Posts.query.order_by(Posts.date_posted.desc()).limit(3)
    return render_template('index.html', posts=posts)

## user routes ###
@app.route('/user/list', methods=['POST','GET'])
def user_list():
    our_users = Users.query.order_by(Users.created)

    return render_template('user_list.html', our_users=our_users)

@app.route('/user/add', methods=['GET','POST'])
def user_add():

    form = UserForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(
                name=form.name.data,
                email=form.email.data,
                password_hash=bcrypt.generate_password_hash(form.password.data)
            )
            db.session.add(user)
            db.session.commit()
        form.name.data = ''
        form.email.data = ''
        flash("user Added Successfully!","success")
        return redirect(url_for('user_list'))

    return render_template('user_add.html', form=form)

@app.route('/user/update/<int:id>', methods=['POST','GET'])
def user_update(id):
    user = UserForm()
    user_to_update = Users.query.get_or_404(id)

    if request.method == "POST":
        user_to_update.name = request.form['name']
        user_to_update.email = request.form['email']
        user_to_update.password_hash = bcrypt.generate_password_hash(request.form['password'])

        try:
            db.session.commit()
            flash("User Update Successfully!","success")
            return redirect(url_for('user_list'))
        except:
            flash("Error! Look like there was a problem...try again!","warning")

    return render_template("user_update.html",form=user, user_to_update=user_to_update)

@app.route('/user/delete/<int:id>')
def user_delete(id):
    user_to_delete = Users.query.get_or_404(id)

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("user Delete Sucessfully!","success")
    except:
        flash("Error! Look like there was a problem...try again!","warning")

    return redirect(url_for('user_list'))

@app.route('/user/login', methods=['POST','GET'])
def user_login():
    form = LoginForm()

    if form.validate_on_submit():

        user_to_login = Users.query.filter_by(email=request.form['email']).first()

        if user_to_login:
            if bcrypt.check_password_hash(user_to_login.password_hash, request.form['password']):
                #flash('Loggin success!', 'success')
                session['email'] = user_to_login.email
                session['name'] = user_to_login.name
                session['user_id'] = user_to_login.id
                return redirect(url_for('user_profile', id=user_to_login.id))
            else:
                flash('User or Password Must Match!!', 'danger')
        else:
            flash('User do not found in DB!', 'danger')

    return render_template("user_login.html", form=form)

@app.route('/user/profile/<int:id>', methods=['POST','GET'])
def user_profile(id):
    user_profile = Users.query.get_or_404(id)
    user_posts = Posts.query.filter_by(author=user_profile.name)

    return render_template('user_profile.html', user=user_profile, your_posts=user_posts)

### post routes ###
@app.route('/post/add', methods=['GET','POST'])
def post_add():
    form = PostForm()

    if form.validate_on_submit():
        post = Posts(
            title = form.title.data,
            slug = form.slug.data,
            author = form.author.data,
            content = form.content.data
        )

        try:
            db.session.add(post)
            db.session.commit()
            flash('Blog Post Submitted Successfully!', 'success')
        except:
            db.session.rollback()
            flash("Error on add post","danger")

        return redirect(url_for('user_profile', id=session['user_id']))

    return render_template("post_add.html", form=form)

@app.route('/post/read_more/<int:id>', methods=['GET','POST'])
def post_read_more(id):
    post = Posts.query.get_or_404(id)

    return render_template("post_read_more.html", post=post)


#custom error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500


#Start app
if __name__ == '__main__':
    app.run(debug=True)
