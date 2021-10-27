from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


#Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(
            request.form["password"],
            method='pbkdf2:sha256',
            salt_length=8
        )
        name = request.form["name"]
        new_db_entry = User(
            email=email,
            password=password,
            name=name
        )
        user = User.query.filter_by(email=email)
        if user.query.filter_by(email=email).first():
            flash("This username is already in use.")
            return redirect(url_for('register'))
        else:
            db.session.add(new_db_entry)
            db.session.commit()
            return render_template("secrets.html", name=name)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        email = request.form["email"]
        user = db.session.query(User).filter_by(email=email).first()
        if not user:
            flash("User does not exist in database. Please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, request.form["password"]):
            flash("Incorrect password. Please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user, remember=False, duration=None, force=False, fresh=True)
            return redirect(url_for('secrets'))


@app.route('/secrets')
@login_required
def secrets():
    if not current_user.is_authenticated:
        return app.login_manager.unauthorized()
    else:
        return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    app.config['PDF_DIR'] = 'static/files'
    return send_from_directory(
        directory=app.config['PDF_DIR'],
        filename=filename,
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
