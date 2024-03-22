from flask import Flask, request, render_template, redirect, url_for, request, session, flash
from flask_sockets import Sockets
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pyrebase
import unittest
import random
import gevent
import time
import json

config = {
    "apiKey": "AIzaSyAQ5hGqYZKXYAdUh5m2MT0z7OGtFdn-u1w",
    "authDomain": "iotlab-aef8a.firebaseapp.com",
    "databaseURL": "https://iotlab-aef8a-default-rtdb.firebaseio.com",
    "projectId": "iotlab-aef8a",
    "storageBucket": "iotlab-aef8a.appspot.com",
    "messagingSenderId": "327373687257",
    "appId": "1:327373687257:web:025ed54253d2bb5b56f1c8",
    "measurementId": "G-4DNH5TNX14"
}


def get_stored_data(fbdb, amount):
    result = []
    response = fbdb.child(
        "StoredData").order_by_key().limit_to_last(amount).get()
    for item in response:
        time = datetime.utcfromtimestamp(
            int(item.key())).strftime('%Y-%m-%d %H:%M:%S')
        humidity = list(list(item.val().values())[0].values())[0]
        moisture = list(list(item.val().values())[0].values())[1]
        temperature = list(list(item.val().values())[0].values())[2]
        if((time != None) & (humidity != None) & (temperature != None) & (moisture != None)):
            result.append({"time": time, "humidity": humidity,
                           "moisture": moisture, "temperature": temperature})
        # print(datetime.utcfromtimestamp(
        #    int(item.key())).strftime('%Y-%m-%d %H:%M:%S'))
        # print("humidity:" +
        #      str(list(list(item.val().values())[0].values())[0]))
        # print("moisture:" +
        #      str(list(list(item.val().values())[0].values())[1]))
        # print("temperature:" +
        #      str(list(list(item.val().values())[0].values())[2]))
    return result


def get_irrigation_type(fbdb):
    return fbdb.child("LiveData").child("IrrigationType").get().val()


def get_irrigation_status(fbdb):
    return fbdb.child("LiveData").child("IrrigationStatus").get().val()


def get_moisture_limit(fbdb):
    return fbdb.child("LiveData").child("MoistureLowerLimit").get().val()


def enable_auto(fbdb):
    fbdb.child("LiveData").child("IrrigationType").set("automatic")


def disable_auto(fbdb):
    fbdb.child("LiveData").child("IrrigationType").set("manual")


def enable_irrigation(fbdb):
    fbdb.child("LiveData").child("IrrigationStatus").set("on")


def disable_irrigation(fbdb):
    fbdb.child("LiveData").child("IrrigationStatus").set("off")


def set_lower_limit(fbdb, moisture):
    fbdb.child("LiveData").child("MoistureLowerLimit").set(moisture)


firebase = pyrebase.initialize_app(config)

fbdbo = firebase.database()
'''
some stuff for getting data from sensors
sockets = Sockets(app)
@sockets.route('/echo')
def echo_socket(ws):
	while not ws.closed():
		message = ws.receive()
		ws.send(message)
'''
db = SQLAlchemy()
app = Flask(__name__)

app.config['SECRET_KEY'] = 'Boogie-woogie'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    # primary keys are required by SQLAlchemy
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


class SensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    temperature = db.Column(db.Float)
    humidity = db.Column(db.Float)
    moisture = db.Column(db.Float)
    tank_water_level = db.Column(db.Boolean)
    irrigation_status = db.Column(db.Boolean)
    datetime = db.Column(db.DateTime, default=datetime.utcnow)


class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    datetime = db.Column(db.DateTime, default=datetime.utcnow)
    prediction = db.Column(db.String(100))


# @app.route('/updateData')
# def sensor():
#    sd = SensorData(temperature=getRandom(), humidity=getRandom(
#    ), moisture=getRandom(), tank_water_level=True, irrigation_status=False)
#    db.session.add(sd)
#    db.session.commit()
#    return redirect(url_for('index'))


# @app.route('/updatePrediction')
# def predict():
#    pd = Prediction(prediction='whatever')
#    db.session.add(pd)
#    db.session.commit()
#    return redirect(url_for('index'))


@app.route('/view')
@login_required
def view():
    return render_template('sensor.html', data=SensorData.query.all(), prediction=Prediction.query.all()[-1])


@app.route('/control')
@login_required
def control():
    return render_template('control.html', data=get_stored_data(fbdbo, 100), irrigationType=get_irrigation_type(fbdbo), IrrigationStatus=get_irrigation_status(fbdbo), moistureLimit=get_moisture_limit(fbdbo))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)


@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    # if this returns a user, then the email already exists in database
    user = User.query.filter_by(email=email).first()

    if user:  # if a user is found, we want to redirect back to signup page so user can try again
        return redirect(url_for('signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name,
                    password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/setmoisture', methods=['POST'])
@login_required
def set_moisture():
    new = float(request.form.get('limit'))
    if new > 80.0 or new < 20.0:
        flash('Please set limit between 20 and 80 percents')
        return redirect(url_for('control'))
    else:
        set_lower_limit(fbdbo, new)
        flash('New limit has been set')
        return redirect(url_for('control'))


@app.route('/switchtype')
@login_required
def switch_type():
    if get_irrigation_type(fbdbo) == "automatic":
        disable_auto(fbdbo)
        flash('Mode was set to auto')
    else:
        enable_auto(fbdbo)
        flash('Mode was set to manual')
    return redirect(url_for('control'))


@app.route('/switchstatus')
@login_required
def switch_status():
    if get_irrigation_status(fbdbo) == "on":
        disable_irrigation(fbdbo)
        flash('Irrigation was disabled manually')
    else:
        enable_irrigation(fbdbo)
        flash('Irrigation was enabled manually')
    return redirect(url_for('control'))

# @app.route('/switchstatus')
# @login_required
# def switch_type():
#    return


@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        # if the user doesn't exist or password is wrong, reload the page
        return redirect(url_for('login'))

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('profile'))


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


def getRandom():
    return random.uniform(0.0, 100.0)


if __name__ == '__main__':
    # print(SensorData.query.all())
    db.create_all(app=app)
    app.run(debug=True)
