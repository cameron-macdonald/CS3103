#!/usr/bin/env python3
import sys
from flask import Flask, jsonify, abort, request, make_response, session
from flask_restful import reqparse, abort, Resource, Api
from flask_session import Session
import json
import pymysql.err
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import *
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
        if not request.json or 'email' not in request.json:
            abort(400, message="Missing required fields")  # Bad request

        # Extract fields from JSON request
        email = request.json.get('email')
        first = request.json.get('first')
        last = request.json.get('last')
        username = request.json.get('username')
        password = request.json.get('password')

        sqlProc = 'addUser'
        sqlArgs = [email, first, last, username, password]  # Pass username as well

        try:
            result = db_access(sqlProc, sqlArgs)  
            user_id = result[0]  # Extract the user ID
            return make_response(jsonify({"status": "success", "user_id": user_id}), 201)
        except Exception as e:
            abort(500, message="Error: please try again")  # Catch any other errors



class OtherUser(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/users/email/first/last/date
	def get(self, email, first, last, date):
		sqlProc = 'getUserBy'
		sqlArgs = [email, first, last, date,]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it	



class SignIn(Resource):
	#
	# Set Session and return Cookie
	#
	# Example curl command:
	# curl -i -H "Content-Type: application/json" -X POST -d '{"username": "Casper", "password": "crap"}'
	#  	-c cookie-jar -k https://cs3103.cs.unb.ca:61340/signin
	#
	def post(self):

		if not request.json:
			abort(400) # bad request

		# Parse the json
		parser = reqparse.RequestParser()
		try:
 			# Check for required attributes in json document, create a dictionary
			parser.add_argument('username', type=str, required=True)
			parser.add_argument('password', type=str, required=True)
			request_params = parser.parse_args()
		except:
			abort(400) # bad request

		if request_params['username'] in session:
			return redirect(url_for('dashboard')) #Redirect if already logged in

		try:
			ldapServer = Server(host=settings.LDAP_HOST)
			ldapConnection = Connection(ldapServer,
				raise_exceptions=True,
				user='uid='+request_params['username']+', ou=People,ou=fcs,o=unb',
				password = request_params['password'])
			ldapConnection.open()
			ldapConnection.start_tls()
			ldapConnection.bind()
			# At this point we have sucessfully authenticated.
			session['username'] = request_params['username']
			return redirect(url_for('dashboard'))  # Redirect after successful login

		except LDAPException:
			response = {'status': 'Access denied'}
			responseCode = 403
		finally:
			ldapConnection.unbind()

		return make_response(jsonify(response), responseCode)

	# GET: Check Cookie data with Session data
	#
	# Example curl command:
	# curl -i -H "Content-Type: application/json" -X GET -b cookie-jar
	#	-k https://cs3103.cs.unb.ca:61340/signin
	def get(self):
		success = False
		if 'username' in session:
			username = session['username']
			response = {'status': 'success'}
			responseCode = 200
		else:
			response = {'status': 'fail'}
			responseCode = 403

		return make_response(jsonify(response), responseCode)

	# DELETE: Check Cookie data with Session data
	#
	# Example curl command:
	# curl -i -H "Content-Type: application/json" -X DELETE -b cookie-jar
	#	-k https://info3103.cs.unb.ca:61340/signin

	def delete(self):
		if 'username' in session:
			session.pop('username')
			response = {'status': 'successfully logged out'}
			return response, 200
		else:
			response = {'status': 'fail'}
			responseCode = 403

		return make_response(jsonify(response), responseCode)





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
