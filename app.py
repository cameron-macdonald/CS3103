#!/usr/bin/env python3
import sys
from flask import Flask, jsonify, abort, request, make_response, session
from flask_restful import reqparse, abort, Resource, Api
from flask_session import Session
import json
import bcrypt
import pymysql.err
import ssl #include ssl libraries
from flask_mail import Mail, Message

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
def registerPage():
    return render_template('index.html')

####################################################################################
#Routing: to dashboard
@app.route('/dashboard')
def dashboardPage():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return render_template('login.html')  # Make sure 'home' is a valid route
####################################################################################
@app.route('/login')
def homePage():
    return render_template('login.html')
####################################################################################
#@app.route('/presentlist/<int:list_id>')
#def view_present_list(list_id):
#    return render_template('presentlist.html', list_id=list_id)

####################################################################################
@app.route('/settings')
def settingsPage():
    if 'username' in session:
        return render_template('settings.html', username=session['username'])
    else:
        return render_template('login.html')  # Make sure 'home' is a valid route
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
	
    def get(self, id=None):
        if id is None:
            sqlProc = "getUsers"
            sqlArgs = []
        else:
            sqlProc = "getUserById"
            sqlArgs = [id]
        try:
            rows = db_access(sqlProc, sqlArgs)  # Fetch users from DB

            for row in rows:
                row.pop("password", None)  # Removes 'password' key if it exists

        except Exception as e:
            abort(500, message=str(e))  # Return server error

        return make_response(jsonify({'users': rows}), 200)  # Return JSON response

    def delete(self, id):
        # Ensure user is logged in
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")  # 401 Unauthorized
		
        if id is None:
            abort(400, message="User ID is required")  # Bad request

        # Ensure the user can only delete their own account
        if int(id) != session['user_id']:
            abort(403, message="Forbidden: You can only delete your own account") 

        sqlProc = "deleteUser"  # Stored procedure to delete a user
        sqlArgs = [id]

        try:
            result = db_access(sqlProc, sqlArgs)  # Call DB function

            if result is None or result == 0:  # Check if user existed
                abort(404, message="User not found")  # Not found

            return make_response(jsonify({"status": "success", "message": "User deleted"}), 200)

        except Exception as e:
            abort(500, message=str(e))  # Server error

    def put(self):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")

        # Get the data from the request
        user_id = session['user_id']
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        email = request.json.get('email')
        old_password = request.json.get('old_password')
        new_password = request.json.get('new_password')

        # Fetch the user's current hashed password from the database
        sqlProc = 'getUserById'  # Assuming you have a stored procedure that gets a user by ID
        sqlArgs = [user_id]

        try:
            result = db_access(sqlProc, sqlArgs)
            if not result:
                abort(404, message="User not found")

            current_hashed_password = result[0]['password']

            # If a new password is provided, verify the old password
            if new_password:
                if not bcrypt.checkpw(old_password.encode('utf-8'), current_hashed_password.encode('utf-8')):
                    abort(400, message="Old password is incorrect")
                
                # Hash the new password
                new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            else:
                new_hashed_password = current_hashed_password  # Keep the current password if no new password is provided

            # Update the user's information
            sqlProc = 'updateUser'  # Assuming you have a stored procedure for updating user
            sqlArgs = [user_id, first_name, last_name, email, new_hashed_password]

            db_access(sqlProc, sqlArgs)

            return make_response(jsonify({"status": "success", "message": "User information updated"}), 200)

        except Exception as e:
            abort(500, message="Error updating user information: " + str(e))

class UserPresentLists(Resource):
    def get(self, id):
        sqlProc = "getListsByUserID"
        sqlArgs = [id]

        try:
            present_lists = db_access(sqlProc, sqlArgs)  # Call stored procedure
            return make_response(jsonify({'present_lists': present_lists}), 200)
        except Exception as e:
            abort(500, message=f"Error fetching present lists: {str(e)}")

class PresentList(Resource):
    def get(self, list_id=None):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")

        user_id = session['user_id']  # Get the user_id from the session
        
        try:
            if list_id:
                sqlProc = 'getListByID'  # Stored procedure to get a single present list
                sqlArgs = [list_id]  # Pass only the list_id
            else:  # If no ID is provided, fetch all present lists for the user
                sqlProc = 'getLists'
                sqlArgs = []

            result = db_access(sqlProc, sqlArgs)  # Fetch data from DB
            
            if not result:
                print('No data found')  # Log this if no data is found
                return make_response(jsonify([]), 200)  # Return empty list if no data

            return make_response(jsonify(result), 200)  # Return a JSON response with status 200
        except Exception as e:
            print(f"Error: {str(e)}")  # Log the error
            abort(500, message="Error fetching present lists")

    # Create a new Present List
    def post(self):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")
        
        if not request.json or 'name' not in request.json or 'occasion' not in request.json:
            abort(400, message="Missing required fields: 'name' and 'occasion'")

        name = request.json.get('name')
        occasion = request.json.get('occasion')
        user_id = session['user_id']  # Get the user_id from the session

        sqlProc = 'addList'  # Updated stored procedure for adding the list with userID
        sqlArgs = [user_id, name, occasion]  # Pass the user_id to associate with the present list

        try:
            result = db_access(sqlProc, sqlArgs)  # Call the db_access function to execute the stored procedure
            if not result:
                raise Exception("Failed to create present list. No result returned.")
            
            # Send success response
            return make_response(jsonify({"status": "success", "message": "Present list created"}), 201)
        
        except Exception as e:
            print(f"Error: {str(e)}")
            return make_response(jsonify({"status": "error", "message": f"Error creating present list: {str(e)}"}), 500)

    # Delete Present List by ID
    def delete(self, list_id):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")

        if not list_id:
            abort(400, message="Present List ID is required")

        user_id = session['user_id']  # Get the user_id from the session

        # Check if the present list belongs to the logged-in user
        sqlProc = 'getListByUserID'  # Procedure to check ownership
        sqlArgs = [user_id, list_id]

        ownership_check = db_access(sqlProc, sqlArgs)

        if not ownership_check:
            abort(403, message="Forbidden: You can only delete your own present lists")  # Move outside try-except

        # Proceed with deletion if the list belongs to the user
        try:
            sqlProc = 'deleteList'  # Stored procedure for deletion
            sqlArgs = [list_id]  # Only list_id is needed

            result = db_access(sqlProc, sqlArgs)

            if result is None or result == 0:
                abort(404, message="Present list not found")

            return make_response(jsonify({"status": "success", "message": "Present list deleted"}), 200)

        except Exception as e:
            print(f"Error deleting list: {str(e)}")  # Log the actual error
            abort(500, message="Error deleting present list")


    # Update (Replace) Present List Information
    def put(self, list_id):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")

        if not list_id:
            abort(400, message="Present List ID is required")

        # Expect all fields for a full update
        new_name = request.json.get('name')
        new_occasion = request.json.get('occasion')

        if not new_name or not new_occasion:
            abort(400, message="Both 'name' and 'occasion' fields are required")

        sqlProc = 'updateList'  # Stored procedure to update present list info
        sqlArgs = [session['user_id'], list_id, new_name, new_occasion]  # Ensure all required fields are included

        try:
            db_access(sqlProc, sqlArgs)  # Update present list info in DB
            return make_response(jsonify({"status": "success", "message": "Present list updated"}), 200)
        except Exception as e:
            abort(500, message=f"Error updating present list information: {str(e)}")

class Login(Resource):
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
            user_id = result[0]['userID'] # Assuming password is the first field

            # Verify password
            if bcrypt.checkpw(entered_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                session['user_id'] = user_id
                session['username'] = username
                session['logged_in'] = True

                return make_response(jsonify({"status": "success", "message": "Login successful"}), 200)
            else:
                abort(401, message="Invalid username or password")  # Unauthorized

        except Exception as e:
            abort(500, message="Error: please try again")  # Catch any other errors

class Logout(Resource):
    def post(self):
        if 'username' not in session:
            abort(400, message="Error: Cannot Log Out")

        try:
            session.clear()  # Properly deletes all session data
            return make_response(jsonify({"status": "success", "message": "Logout successful"}), 200)

        except Exception as e:
            abort(500, message="Error: please try again")  # Catch any other errors

class Settings(Resource):
    def get(self):
        try:
            if "user_id" not in session:
                abort(401, message="Unauthorized: Please log in")

            sqlProc = "getUserById"
            sqlArgs = [session["user_id"]]

            result = db_access(sqlProc, sqlArgs)  # Fetch user data
            if not result:
                abort(404, message="User not found")  # More accurate error

            return make_response(jsonify({"status": "success", "data": result[0]}), 200)

        except Exception as e:
            print(f"Error: {e}")  # Logs error for debugging
            abort(500, message="Internal server error, please try again")

class Present(Resource):
    def get(self, list_id):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")

        sqlProc = 'getPresentsByListID'
        sqlArgs = [list_id]

        try:
            result = db_access(sqlProc, sqlArgs)
            return make_response(jsonify(result), 200) if result else make_response(jsonify([]), 200)
        except Exception as e:
            abort(500, message=str(e))


####################################################################################
#
# Identify/create endpoints and endpoint objects
#
api = Api(app)
api.add_resource(Login, '/Auth/Login')
api.add_resource(Logout, '/Auth/Logout')
api.add_resource(User, "/user", "/user/<int:id>")
api.add_resource(UserPresentLists, "/user/<int:id>/presentlist")
api.add_resource(PresentList, '/presentlist', "/presentlist/<int:list_id>")
api.add_resource(Settings,"/user/update")
api.add_resource(Present, '/present/<int:list_id>')


#############################################################################
if __name__ == "__main__":

	context = ('cert.pem', 'key.pem') # Identify the certificates you've generated.
	app.run(host=settings.APP_HOST, port=settings.APP_PORT, ssl_context=context,debug=settings.APP_DEBUG)
