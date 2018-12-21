from flask import Flask, render_template, request, redirect,flash, url_for
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import datetime
import os


prev_count = 0
file_path = os.path.abspath(os.getcwd())+"\Demo\database.db"

app = Flask(__name__)
app.secret_key = "dontsharethis"
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    userid = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    type = db.Column(db.String(80))


class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incorrect = db.Column(db.String(100))
    correct = db.Column(db.String(100))
    userid = db.Column(db.String(100))
    comments = db.Column(db.String(100))
    date_added = db.Column(db.DateTime, default=datetime.datetime.now)

class AllData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incorrect = db.Column(db.String(100))
    correct = db.Column(db.String(100))
    userid = db.Column(db.String(100))
    comments = db.Column(db.String(100))
    date_added = db.Column(db.DateTime, default=datetime.datetime.now)

class Verifier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(15), unique=True)
    name = db.Column(db.String(50))

class Manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(15), unique=True)
    name = db.Column(db.String(50))

class Acknowledge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incorrect = db.Column(db.String(100))
    correct = db.Column(db.String(100))
    userid = db.Column(db.String(100))
    date_added = db.Column(db.DateTime, default=datetime.datetime.now)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    feedback = db.Column(db.String(500))
    userid = db.Column(db.String(100))
    date_added = db.Column(db.DateTime, default=datetime.datetime.now)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    userid = StringField('userid', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField('remember me')
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    name = StringField('name', validators=[InputRequired(), Length(max=50)])
    userid = StringField('userid', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80)])


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm()
    error=None
    if form.validate_on_submit():
        user = User.query.filter_by(userid=form.userid.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                verifier_list = db.engine.execute('select userid from verifier')
                manager_list = db.engine.execute('select userid from manager')
                for verifier in verifier_list:
                    if user.userid == verifier[0]:
                        return redirect("/verifier")
                for manager in manager_list:
                    if user.userid == manager[0]:
                        return redirect("/manager")
                return redirect("/transcriber")
            else:
                error = "Invalid password"
        else:
            error = "Invalid user"
    return render_template("login.html", form=form,error=error)

@app.route('/signup', methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    error = None
    if form.validate_on_submit():
        userid = form.userid.data
        users_list = db.engine.execute('select userid from user')
        verifier_list = db.engine.execute('select userid from verifier')
        manager_list = db.engine.execute('select userid from manager')
        user_exists = False
        for user in users_list:
            if userid == user[0]:
                user_exists = True
                break
        if user_exists:
            error = "User already registered"
        else:
            other_user = True
            for verifier in verifier_list:
                if userid == verifier[0]:
                    hashed_password = generate_password_hash(form.password.data, method='sha256')
                    type = 'verifier'
                    new_user = User(name=form.name.data, userid=form.userid.data, password=hashed_password, type=type)
                    other_user = False
            for manager in manager_list:
                if userid == manager[0]:
                    hashed_password = generate_password_hash(form.password.data, method='sha256')
                    type = 'manager'
                    new_user = User(name=form.name.data, userid=form.userid.data, password=hashed_password, type=type)
                    other_user = False
            if other_user:
                hashed_password = generate_password_hash(form.password.data, method='sha256')
                type = 'other'
                new_user = User(name=form.name.data, userid=form.userid.data, password=hashed_password, type=type)
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')
    return render_template("signup.html", form=form, error=error)

@app.route('/verifier')
@login_required
def verifier():
    user_types = db.engine.execute("SELECT type from user WHERE userid = :param", {"param" : current_user.userid})
    for user_type in user_types:
        if (user_type[0] == "other"):
            error = "Sorry ! Only verifiers can access this page. Please contact @sebyj or @sssndh for help"
            return redirect("/transcriber")
    rows = db.engine.execute("SELECT incorrect,correct,userid,comments,strftime('%d-%m-%Y %H:%M',date_added) FROM data;")
    contributions = db.engine.execute("SELECT userid, count(userid) from all_data group by userid order by count(userid) desc limit 10;")
    return render_template("verifier_view.html", rows=rows, current_user=current_user, contributions=contributions)

@app.route('/verifier_list')
@login_required
def verifier_list():
    rows = db.engine.execute("SELECT userid,name FROM verifier;")
    return render_template("verifier_list.html", rows=rows)

@app.route('/verifier/add_data', methods=["POST"])
@login_required
def verifier_add_data():
    incorrect = request.form['incorrectTranscription']
    correct = correct=request.form['correctTranscription']
    userid = userid=current_user.userid
    comments=request.form['comments'].replace('/','\\')
    new_entry = AllData(incorrect=incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('verifier_add_data_to_db', incorrect=incorrect, correct=correct, userid=userid, comments=comments, direct='false'))

@app.route('/verifier/delete_data/<correct>')
@login_required
def verifier_delete_data_from_db(correct):
    db.engine.execute("DELETE FROM data WHERE correct= :param", {"param" : correct})
    db.session.commit()
    return redirect('/verifier')

@app.route('/verifier/add_data_to_db/<incorrect>/<correct>/<userid>/<comments>/<direct>')
@login_required
def verifier_add_data_to_db(incorrect, correct, userid, comments, direct):
    global updated
    id_delete = None
    new_entry = Data()
    rows = db.engine.execute("SELECT id, incorrect, correct, userid FROM data WHERE correct = :param", {"param" : correct})
    rows = rows.fetchall()
    print (rows)
    if rows:
        db_incorrect = rows[0][1]
        id_delete = rows[0][0]
        if incorrect not in db_incorrect:
            db_incorrect = db_incorrect + ", " + incorrect
        new_entry = Data(incorrect=db_incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
    else:
        new_entry = Data(incorrect=incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
    if id_delete:
        db.engine.execute("DELETE FROM data where id=:param", {"param":id_delete})
    if direct == 'true':
        new_entry2 = AllData(incorrect=incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
        db.session.add(new_entry2)

    db.session.add(new_entry)
    db.session.commit()
    return redirect('/verifier')

@app.route('/manager')
@login_required
def manager():
    user_types = db.engine.execute("SELECT type from user WHERE userid = :param", {"param" : current_user.userid})
    for user_type in user_types:
        if (user_type[0] == "other"):
            return redirect('/transcriber')
        elif (user_type[0] == "verifier"):
            return redirect('/verifier')
    rows = db.engine.execute("SELECT incorrect,correct,userid,comments,strftime('%d-%m-%Y %H:%M',date_added) FROM data;")
    acknowledgements = db.engine.execute("SELECT userid, count(userid) from acknowledge group by userid order by count(userid) desc limit 10;")
    contributions = db.engine.execute("SELECT userid, count(userid) from all_data group by userid order by count(userid) desc limit 10;")
    return render_template("manager_view.html", rows=rows, current_user=current_user,contributions=contributions, acknowledgements=acknowledgements)

@app.route('/manager_list')
@login_required
def manager_list():
    rows = db.engine.execute("SELECT userid,name FROM manager;")
    return render_template("manager_list.html", rows=rows)

@app.route('/manager/add_data', methods=["POST"])
@login_required
def manager_add_data():
    incorrect = request.form['incorrectTranscription']
    correct = correct=request.form['correctTranscription']
    userid = userid=current_user.userid
    comments=request.form['comments'].replace('/','\\')
    new_entry = AllData(incorrect=incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('manager_add_data_to_db', incorrect=incorrect, correct=correct, userid=userid, comments=comments, direct='false'))

@app.route('/manager/add_data_to_db/<incorrect>/<correct>/<userid>/<comments>/<direct>')
@login_required
def manager_add_data_to_db(incorrect, correct, userid, comments, direct):
    global updated
    id_delete = None
    new_entry = Data()
    rows = db.engine.execute("SELECT id, incorrect, correct, userid FROM data WHERE correct = :param", {"param" : correct})
    rows = rows.fetchall()
    print (rows)
    if rows:
        db_incorrect = rows[0][1]
        id_delete = rows[0][0]
        if incorrect not in db_incorrect:
            db_incorrect = db_incorrect + ", " + incorrect
        new_entry = Data(incorrect=db_incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
    else:
        new_entry = Data(incorrect=incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
    if id_delete:
        db.engine.execute("DELETE FROM data where id=:param", {"param":id_delete})
    if direct == 'true':
        new_entry2 = AllData(incorrect=incorrect, correct=correct, userid=userid, comments=comments, date_added = datetime.datetime.now())
        db.session.add(new_entry2)
    db.session.add(new_entry)
    db.session.commit()
    return redirect('/manager')

@app.route('/manager/delete_data/<correct>')
@login_required
def manager_delete_data_from_db(correct):
    db.engine.execute("DELETE FROM data WHERE correct= :param", {"param" : correct})
    db.session.commit()
    return redirect('/manager')

@app.route('/manager/add_verifier', methods=["POST"])
@login_required
def manager_add_verifier():
    new_verifier = Verifier(userid=request.form['userid'], name=request.form['fullname'])
    db.session.add(new_verifier)
    db.session.commit()
    return redirect('/manager')

@app.route('/manager/add_manager', methods=["POST"])
@login_required
def manager_add_manager():
    new_manager = Manager(userid=request.form['userid'], name=request.form['fullname'])
    db.session.add(new_manager)
    db.session.commit()
    return redirect('/manager')


@app.route('/transcriber')
@login_required
def transcriber():
    diff = 0
    rows1 = db.engine.execute("SELECT incorrect,correct,userid,comments,date_added FROM data;")
    rows = db.engine.execute("SELECT incorrect,correct,userid,comments,strftime('%d-%m-%Y %H:%M',date_added) FROM data;")
    acknowledgements = db.engine.execute("SELECT correct from acknowledge where userid = :param", { "param" : current_user.userid })
    acks = []
    for ack in acknowledgements:
        acks.append(ack[0])
    count = len(rows1.fetchall())
    diff = checkDiff(count)
    acknowledgements = db.engine.execute("SELECT userid, count(userid) from acknowledge group by userid order by count(userid) desc limit 10;")
    return render_template("transcriber_view.html", rows=rows, diff=diff, acks=acks, acknowledgements=acknowledgements)

@app.route('/transcriber/acknowledge/<incorrect>/<correct>')
@login_required
def acknowledge(incorrect, correct):
    new_entry = Acknowledge(incorrect=incorrect, correct=correct, userid=current_user.userid, date_added=datetime.datetime.now())
    db.session.add(new_entry)
    db.session.commit()
    return redirect('/transcriber')

@app.route('/transcriber/acknowledgements')
@login_required
def acknowledgements():
    rows = db.engine.execute("SELECT incorrect, correct, userid, date_added from acknowledge where userid = :param", {"param": current_user.userid})
    return render_template("acknowledgements.html", rows=rows)

@app.route('/verifier/contributions')
@login_required
def contributions():
    rows = db.engine.execute("SELECT incorrect, correct, userid, date_added from all_data where userid = :param", {"param": current_user.userid})
    return render_template("contributions.html", rows=rows)

def checkDiff(count):
    global prev_count
    if count > prev_count:
        res = count - prev_count
        prev_count = count
        return (res)
    return 0

@app.route('/pending_acknowledgements')
@login_required
def pending_ack():
    count = 0
    rows = db.engine.execute("SELECT userid, count(userid) from acknowledge group by userid;")
    rowcount = db.engine.execute("SELECT count(*) FROM data;")
    for row in rowcount:
        count = row[0]
    print (count)
    return render_template("pending_ack.html", rows=rows, count=count)

@app.route('/feedback')
@login_required
def feedback():
    return render_template("feedback.html")

@app.route('/feedback/add', methods=["POST"])
@login_required
def add_feedback():
    title= request.form['title']
    feedback= request.form['feedback']
    new_entry = Feedback(title=title, feedback=feedback, userid=current_user.userid, date_added=datetime.datetime.now())
    db.session.add(new_entry)
    db.session.commit()
    return redirect('manager')

@app.route('/feedbacks')
@login_required
def feedbacks():
    rows = db.engine.execute("SELECT * FROM feedback")
    return render_template("feedbacks.html", rows=rows)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

# db.create_all()

if __name__ == "__main__":
    app.run(host="MAA128CG745067M" , port=8001)
