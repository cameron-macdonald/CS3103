#!/usr/bin/env python3
import sys
from flask import Flask, jsonify, abort, request, make_response, session
from flask_restful import reqparse, abort, Resource, Api
from flask_session import Session
import json
import bcrypt
import pymysql.err
import ssl #include ssl libraries

import settings # Our server and db settings, stored in settings.py
from flask import render_template
from db_util import db_access

app = Flask(__name__)
# Set Server-side session config: Save sessions in the local app directory.
app.secret_key = settings.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_NAME'] = 'peanutButter'
app.config['SESSION_COOKIE_DOMAIN'] = settings.APP_HOST
Session(app)


####################################################################################
#Routing: to home (register) page
@app.route('/')
def register():
    return render_template('index.html')

####################################################################################
#Routing: to dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return render_template('index.html')  # Make sure 'home' is a valid route
####################################################################################
@app.route('/login')
def home():
    return render_template('login.html')
####################################################################################
#
# Error handlers
#
@app.errorhandler(400) # decorators to add to 400 response
def not_found(error):
	return make_response(jsonify( { 'status': 'Bad request' } ), 400)

@app.errorhandler(404) # decorators to add to 404 response
def not_found(error):
	return make_response(jsonify( { 'status': 'Resource not found' } ), 404)

####################################################################################
#
# Routing: GET and POST using Flask-Session
#

class User(Resource):
    def post(self):
        if not request.json or 'email' not in request.json or 'password' not in request.json:
            abort(400, message="Missing required fields")  # Bad request

        # Extract fields from JSON request
        email = request.json.get('email')
        first = request.json.get('first')
        last = request.json.get('last')
        username = request.json.get('username')
        password = request.json.get('password')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        sqlProc = 'addUser'
        sqlArgs = [email, first, last, username, hashed_password]  # Store the hashed password

        try:
            result = db_access(sqlProc, sqlArgs)  
            user_id = result[0]  # Extract the user ID
            return make_response(jsonify({"status": "success", "user_id": user_id}), 201)
        except Exception as e:
            abort(500, message="Error: please try again")  # Catch any other errors

class SignIn(Resource):
    def post(self):
        if not request.json or 'username' not in request.json or 'password' not in request.json:
            abort(400, message="Missing required fields")

        username = request.json.get('username')
        entered_password = request.json.get('password')
        date_created = request.json.get('dateCreated', None)
		
        # Retrieve stored hashed password from the database
        sqlProc = 'getUsersBy'  
        sqlArgs = [
			'',
			'',
			'',
			username,
			date_created if date_created else None
		]

        try:
            result = db_access(sqlProc, sqlArgs)  # Fetch user data
            if not result:
                abort(401, message="Invalid username or password")  # Unauthorized

            stored_hashed_password = result[0]['password'] # Assuming password is the first field

            # Verify password
            if bcrypt.checkpw(entered_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
				
                session['username'] = username
                session['logged_in'] = True

                return make_response(jsonify({"status": "success", "message": "Login successful"}), 200)
            else:
                abort(401, message="Invalid username or password")  # Unauthorized

        except Exception as e:
            abort(500, message="Error: please try again")  # Catch any other errors



####################################################################################
#
# Identify/create endpoints and endpoint objects
#
api = Api(app)
api.add_resource(SignIn, '/signin')
api.add_resource(User, '/user')


#############################################################################
if __name__ == "__main__":

	context = ('cert.pem', 'key.pem') # Identify the certificates you've generated.
	app.run(host=settings.APP_HOST, port=settings.APP_PORT, ssl_context=context,debug=settings.APP_DEBUG)
