from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
import requests
import json
import os
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# instantiate Flask
app = Flask(__name__)
# configures database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.jinja_env.filters['zip'] = zip
# initialize boostrap for flask
Bootstrap(app)
# initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# initialize database
db = SQLAlchemy(app)

# User class
class User(UserMixin, db.Model):
    # add appopriate columns to user table
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    city = db.relationship('CitySearch', backref='owner')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# LoginForm class
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

# RegisterForm class
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

# City class
class City(db.Model):
    # add integer column to database
    id = db.Column(db.Integer, primary_key=True)
    # add city name column to database
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# City Search class
class CitySearch(db.Model):
    # add integer column to database
    id = db.Column(db.Integer, primary_key=True)
    # add city name column to database
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# function that gets weather data for city (imperial)
def getWeatherData(city):
    # set url api
    api = os.getenv('API_KEY')
    url = 'http://api.openweathermap.org/data/2.5/weather?appid={}&q={}&units=imperial'.format(api, city)
    # send a request to api and fetch weather data in json
    data = requests.get(url).json()
    # return json data
    return data

# function that gets weather data for city (metric)
def getWeatherDataMetric(city):
    # set url api
    api = os.getenv('API_KEY')
    url = 'http://api.openweathermap.org/data/2.5/weather?appid={}&q={}&units=metric'.format(api, city)
    # send a request to api and fetch weather data in json
    data = requests.get(url).json()
    # return json data
    return data

# app route to index page
# redirects to login page
@app.route('/')
def index():
    # redirect to login page
    return redirect(url_for('login'))

# app route to login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # instantiate Login Form
    form = LoginForm()

    # check if form has been submitted
    if form.validate_on_submit():
        # fetch user from database
        user = User.query.filter_by(username=form.username.data).first()

        # check if user exists
        if user:
            # check if password is correct
            if check_password_hash(user.password, form.password.data):
                # login the user
                login_user(user, remember=form.remember.data)

                # set temp existing city to check if a city already exists in database for home page
                existingCity = CitySearch.query.filter_by(owner_id=current_user.id).first()

                if not existingCity:
                    # redirect to setCity page
                    return redirect(url_for('setCity'))

                else:
                    # redirect to weather_get
                    return redirect(url_for('weather_get'))

        # display the appropriate message
        flash('Invalid username or password.', 'error')
        # display that username or password is incorrect
        return redirect(url_for('login'))

    # display login page
    return render_template('login.html', form=form)

# app route to sign up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # instantiate Register Form
    form = RegisterForm()

    # check if form has been submitted
    if form.validate_on_submit():
        # check for existing usernames/emails
        existingEmail = User.query.filter_by(email=form.email.data).first()
        existingUsername = User.query.filter_by(username=form.username.data).first()

        # email and username don't exist (i.e. valid)
        if not existingEmail and not existingUsername:
            # hash the password
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            # add user to database
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

            db.session.add(new_user)
            db.session.commit()

            # redirect to login page
            return redirect(url_for('login'))

        # email and username already exist
        elif existingEmail and existingUsername:
            # display appropriate error message
            flash('Username and Email already exist!', 'errorSignup')

        # email alreayd exists
        elif existingEmail:
            # display appropriate error message
            flash('Email already exists!', 'errorSignup')

        # username already exists
        elif existingUsername:
            # display appropriate error message
            flash('Username already exists!', 'errorSignup')

    # display sign up page
    return render_template('signup.html', form=form)

# app route to logout a user
# requires a user to login before receiving access to this feature
@app.route('/logout')
@login_required
def logout():
    # logout the user
    logout_user()
    # redirect to login page
    return redirect(url_for('login'))

# app route to set initial city for home page
# requires a user to login before receiving access to this page
@app.route('/setCity', methods=['GET', 'POST'])
@login_required
def setCity():
    if request.method == "POST":
        # error message set to None because no error message to display
        errMsg = None
        # fetch city from user input
        newCity = request.form.get('city')

        # check if user input exists
        if newCity:
            # set temp existing city if a city already exists in database
            existingCity = CitySearch.query.filter_by(owner_id=current_user.id).all()

            # check if city already exists in database
            if not existingCity:
                # fetch weather data
                newCityData = getWeatherData(newCity)

                # check if city exists in the world
                if newCityData['cod'] == 200:
                    # add new city to the database
                    newCityObj = CitySearch(name=newCity, owner_id=current_user.id)

                    db.session.add(newCityObj)
                    db.session.commit()

                    # redirect to weather_get
                    return redirect(url_for('weather_get'))

                else:
                    # set appropriate error message to variable
                    errMsg = "City does not exist in the world!"

            else:
                # set appropriate error message to variable
                errMsg = "A city has already been selected!"

        if errMsg:
            # display appropriate error message
            flash(errMsg, 'error')

    # display the setCity page
    return render_template('setCity.html')

# app route to weather page with GET method
# this is the page that's displayed once logged in
# requires a user to login before receiving access to this page
@app.route('/weather')
@login_required
def weather_get():
    # get cities from database
    cities = City.query.filter_by(owner_id=current_user.id)

    # create list for weather data of each city
    weatherDataBookmarks = []

    # add cities to list
    for city in cities:
        # create dictionary of needed weather data
        weather = {
            'city' : city.name
        }

        # append dictionary to list
        weatherDataBookmarks.append(weather)

    # display the weather page
    return render_template("weather.html", weatherDataBookmarks=weatherDataBookmarks, length=len(weatherDataBookmarks), name=current_user.username)

# app route to weather page with POST method
# redirects to weather_get
@app.route('/weather', methods=['POST'])
@login_required
def weather_post():
    # error message set to None because no error message to display
    errMsg = None
    # fetch user input
    newCity = request.form.get('city')

    # check if user input exists
    if newCity:
        # set temp existing city if this city already exists in database
        existingCity = City.query.filter_by(name=newCity, owner_id=current_user.id).first()

        # check if city already exists in database
        if not existingCity:
            # get cities from database
            cities = City.query.filter_by(owner_id=current_user.id).all()

            # check if limit reached
            if len(cities) < 6:
                # fetch weather data
                newCityData = getWeatherData(newCity)

                # check if city exists in the world
                if newCityData['cod'] == 200:
                    # add city to database
                    newCityObj = City(name=newCity, owner_id=current_user.id)

                    db.session.add(newCityObj)
                    db.session.commit()

                else:
                    # set appropriate error message to variable
                    errMsg = "City does not exist in the world!"

            else:
                # set appropriate error message to variable
                errMsg = "Bookmark limit reached!"

        else:
            # set appropriate error message to variable
            errMsg = "City already exists in the database!"

    # check if error message exists
    if errMsg:
        # display appropriate error message
        flash(errMsg, 'error')

    else:
        # display appropriate success message
        flash('City added successfully!', 'success')

    # redirect to weather_get
    return redirect(url_for('weather_get'))

# app route to delete cities from bookmarks
# redirects to weather_get
@app.route('/delete/<name>')
@login_required
def delete_city(name):
    # fetch specific city to be deleted from database and delete it
    city = City.query.filter_by(name=name, owner_id=current_user.id).first()
    db.session.delete(city)
    db.session.commit()

    # display appropriate success message
    flash('Successfully deleted {}!'.format(city.name), 'success')

    # redirect to weather_get
    return redirect(url_for('weather_get'))

# app route to display bookmark city on home page
# redirects to weather_get
@app.route('/displayBookmarkCityHome/<name>')
@login_required
def displayBookmarkCityHome(name):
    # set temp existing city if this city already exists in database
    existingCity = CitySearch.query.filter_by(name=name, owner_id=current_user.id).first()

    # check if city already exists in database
    if not existingCity:
        # fetch specific city to be deleted from database and delete it
        city = CitySearch.query.filter_by(owner_id=current_user.id)

        # delete city from database
        for city in city:
            db.session.delete(city)

        # add selected city to database
        newCityObj = CitySearch(name=name, owner_id=current_user.id)

        db.session.add(newCityObj)
        db.session.commit()

        # display appropriate success message
        flash('New city selected successfully!', 'successHome')

    else:
        # display appropriate error message
        flash('City has already been selected!', 'errorHome')

    # redirect to weather_get
    return redirect(url_for('weather_get'))

# app route to search for a city
# redirects to weather_get 
@app.route('/search', methods=['POST'])
@login_required
def searching():
    # error message set to None because no error message to display
    errMsg = None
    # fetch city from user input
    newCity = request.form.get('city_search')

    # check if user input exists
    if newCity:
        # set temp existing city if this city already exists in database
        existingCity = CitySearch.query.filter_by(name=newCity, owner_id=current_user.id).first()

        # check if city already exists in database
        if not existingCity:
            # fetch weather data
            newCityData = getWeatherData(newCity)

            # check if city exists in the world
            if newCityData['cod'] == 200:
                # get city from appropriate table in database (should be only 1 city)
                city = CitySearch.query.filter_by(owner_id=current_user.id)

                # delete city from database
                for city in city:
                    db.session.delete(city)

                # add new city to the database
                newCityObj = CitySearch(name=newCity, owner_id=current_user.id)

                db.session.add(newCityObj)
                db.session.commit()

            else:
                # set appropriate error message to variable
                errMsg = "City does not exist in the world!"

        else:
            # set appropriate error message to variable
            errMsg = "City has already been selected!"

    if errMsg:
        # display appropriate error message
        flash(errMsg, 'errorHome')

    else:
        # display appropriate success message
        flash('New city selected successfully!', 'successHome')

    # redirect to weather_get
    return redirect(url_for('weather_get'))

# app route to update weather without page refresh (imperial)
# returns a json representation of weather info that is updated
@app.route('/update', methods=['GET'])
@login_required
def updateWeatherData():
    # get city displayed from database
    citySearch = CitySearch.query.filter_by(owner_id=current_user.id)

    for city in citySearch:
        # fetch weather data for city
        dataHome = getWeatherData(city.name)

        # create dictionary of needed weather data
        weatherHome = {
            'city' : city.name,
            'temperature' : int(round(dataHome['main']['temp'])),
            'description' : dataHome['weather'][0]['description'].upper(),
            'perceived_temp' : int(round(dataHome['main']['feels_like'])),
            'humidity' : dataHome['main']['humidity'],
            'wind_speed' : round(dataHome['wind']['speed'], 1),
            'pressure' : dataHome['main']['pressure']
        }

    # get cities from database
    cities = City.query.filter_by(owner_id=current_user.id)

    # create list for weather data of each city
    weatherDataBookmarks = []

    # get weather data for each city in the database
    for city in cities:
        # fetch weather data for city
        data = getWeatherData(city.name)

        # create dictionary of needed weather data
        weather = {
            'city' : city.name,
            'temperature' : int(round(data['main']['temp'])),
            'groupDescription' : data['weather'][0]['main']
        }

        # add weather data to list
        weatherDataBookmarks.append(weather)

    # return json representation of weather info
    return jsonify(weatherHome=weatherHome, weatherDataBookmarks=weatherDataBookmarks)

# app route to update weather without page refresh (metric)
# returns a json representation of weather info that is updated
@app.route('/updateMetric', methods=['GET'])
@login_required
def updateWeatherDataMetric():
    # get city displayed from database
    citySearch = CitySearch.query.filter_by(owner_id=current_user.id)

    for city in citySearch:
        # fetch weather data for city
        dataHome = getWeatherDataMetric(city.name)

        # create dictionary of needed weather data
        weatherHome = {
            'city' : city.name,
            'temperature' : int(round(dataHome['main']['temp'])),
            'description' : dataHome['weather'][0]['description'].upper(),
            'perceived_temp' : int(round(dataHome['main']['feels_like'])),
            'humidity' : dataHome['main']['humidity'],
            'wind_speed' : round(dataHome['wind']['speed'], 1),
            'pressure' : dataHome['main']['pressure']
        }

    # get cities from database
    cities = City.query.filter_by(owner_id=current_user.id)

    # create list for weather data of each city
    weatherDataBookmarks = []

    # get weather data for each city in the database
    for city in cities:
        # fetch weather data for city
        data = getWeatherDataMetric(city.name)

        # create dictionary of needed weather data
        weather = {
            'city' : city.name,
            'temperature' : int(round(data['main']['temp'])),
            'groupDescription' : data['weather'][0]['main']
        }

        # add weather data to list
        weatherDataBookmarks.append(weather)

    # return json representation of weather info
    return jsonify(weatherHome=weatherHome, weatherDataBookmarks=weatherDataBookmarks)

# app route to save settings
# redirects to weather_get
@app.route('/saveSettings', methods=['POST'])
@login_required
def saveSettings():
    # redirect to weather_get
    return redirect(url_for('weather_get'))