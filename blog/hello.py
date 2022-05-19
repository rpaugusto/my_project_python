from flask import Flask
from flask import render_template, flash, url_for, request, redirect
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime

#create falsk instance
app = Flask(__name__)
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
    password = db.Column(db.String(256), default='password')
    created = db.Column(db.DateTime, default=db.func.now())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


#create a form class
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("E-Mail", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/user/add', methods=['GET','POST'])
def user_add():

    form = UserForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(name=form.name.data, email=form.email.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        flash("user Added Successfully!","success")
        return render_template(url_for('user_list'))

    return render_template('user_add.html', form=form)

@app.route('/user/list', methods=['POST','GET'])
def user_list():
    our_users = Users.query.order_by(Users.created)

    return render_template('user_list.html', our_users=our_users)

@app.route('/user/update/<int:id>', methods=['POST','GET'])
def user_update(id):
    user = UserForm()
    user_to_update = Users.query.get_or_404(id)

    if request.method == "POST":
        user_to_update.name = request.form['name']
        user_to_update.email = request.form['email']
        user_to_update.password = request.form['password']

        try:
            db.session.commit()
            flash("User Update Successfully!","success")
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
