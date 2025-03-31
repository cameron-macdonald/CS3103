#!/usr/bin/env python3
import re
import sys
from flask import Flask, jsonify, abort, request, make_response, session
from flask_restful import reqparse, abort, Resource, Api
from flask_session import Session
import json
import bcrypt
import pymysql.err
import ssl #include ssl libraries
import smtplib
import hashlib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

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
@app.route('/settings')
def settingsPage():
    if 'username' in session:
        return render_template('settings.html', username=session['username'])
    else:
        return render_template('login.html')  # Make sure 'home' is a valid route
####################################################################################
@app.route('/profile')
def profilePage():
    if 'username' in session:
        return render_template('presentlist.html', username=session['username'])
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
        data = request.json

        # Check if request contains required fields
        if not data or "email" not in data or "password" not in data:
            abort(400, message="Missing required fields")

        email = data.get("email").strip()
        first = data.get("first", "").strip()
        last = data.get("last", "").strip()
        username = data.get("username", "").strip()
        password = data.get("password").strip()

        if not is_valid_input(first) or not is_valid_input(last) or not is_valid_input(username):
            abort(400, message="Invalid characters in name or username.")

        if not is_valid_email(email):
            abort(400, message="Invalid email format")

        if not is_strong_password(password):
            abort(400, message="Password must be at least 8 characters, contain an uppercase, lowercase, digit, and special character")

        # Hash the password securely
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        sqlProc = "addUser"
        sqlArgs = [email, first, last, username, hashed_password]

        try:
            result = db_access(sqlProc, sqlArgs)  
            user_id = result[0]["id"]

            # Send email verification
            response_data = generate_verification_token(user_id)
            verification_token = response_data.get("token")
            verification_link = f"https://cs3103.cs.unb.ca:8013/verification-token/verify?userId={user_id}&token={verification_token}"
            send_verification_email(email, verification_link)

            return make_response(jsonify({"status": "success", "user_id": user_id}), 201)
        except Exception as e:
            abort(500, message="Error: please try again")
	
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
        username = request.json.get('username')
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        email = request.json.get('email')
        old_password = request.json.get('old_password')
        new_password = request.json.get('new_password')


        if not is_valid_input(first_name) or not is_valid_input(last_name) or not is_valid_input(username):
            abort(400, message="Invalid characters in name or username.")

        if not is_valid_email(email):
            abort(400, message="Invalid email format")

        if not is_strong_password(new_password):
            abort(400, message="New password must be at least 8 characters, contain an uppercase, lowercase, digit, and special character")


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
            sqlArgs = [user_id, username, first_name, last_name, email, new_hashed_password]

            db_access(sqlProc, sqlArgs)

            return make_response(jsonify({"status": "success", "message": "User information updated"}), 200)

        except Exception as e:
            abort(500, message="Error updating user information: " + str(e))

class UserSearch(Resource):
    def get(self):
        user_id = request.args.get('userID', None)
        email = request.args.get('email', None)
        first_name = request.args.get('firstName', None)
        last_name = request.args.get('lastName', None)
        username = request.args.get('username', None)
        email_verified = request.args.get('email_verified', None)

        # Convert data types if necessary
        if user_id is not None:
            user_id = int(user_id)

        if email_verified is not None:
            email_verified = bool(int(email_verified))  # Convert '0' or '1' to Boolean

        try:
            # Call stored procedure with the provided parameters
            sqlProc = 'searchUsers'  # Stored procedure for searching users
            sqlArgs = [user_id, email, first_name, last_name, username, email_verified]
            
            rows = db_access(sqlProc, sqlArgs)  # Query DB

            return make_response(jsonify({'users': rows}), 200)

        except Exception as e:
            abort(500, message=f"Error searching users: {str(e)}")

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


        if not is_valid_input(name) or not is_valid_input(occasion):
            abort(400, message="Invalid characters in name or occasion.")

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

        user_id = session['user_id'] 

        # Check if the present list belongs to the logged-in user
        sqlProc = 'getListByUserID' 
        sqlArgs = [user_id, list_id]

        ownership_check = db_access(sqlProc, sqlArgs)

        if not ownership_check:
            abort(403, message="Forbidden: You can only delete your own present lists")

        # Proceed with deletion if the list belongs to the user
        try:
            sqlProc = 'deleteList'
            sqlArgs = [user_id, list_id]

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


        if not is_valid_input(new_name) or not is_valid_input(new_occasion):
            abort(400, message="Invalid characters in the new name or occasion.")

        if not new_name or not new_occasion:
            abort(400, message="Both 'name' and 'occasion' fields are required")

        sqlProc = 'updateList'  # Stored procedure to update present list info
        sqlArgs = [session['user_id'], list_id, new_name, new_occasion]  # Ensure all required fields are included

        try:
            db_access(sqlProc, sqlArgs)  # Update present list info in DB
            return make_response(jsonify({"status": "success", "message": "Present list updated"}), 200)
        except Exception as e:
            abort(500, message=f"Error updating present list information: {str(e)}")

class PresentListSearch(Resource):
    def get(self):
        # Extract search parameters from the query string (optional)
        present_list_id = request.args.get('presentListID', None)
        user_id = request.args.get('userID', None)
        name = request.args.get('name', None)
        occasion = request.args.get('occasion', None)
        date_created = request.args.get('dateCreated', None)

        # Convert data types if necessary
        if present_list_id is not None:
            present_list_id = int(present_list_id)

        if user_id is not None:
            user_id = int(user_id)

        try:
            # Call stored procedure with the provided parameters
            sqlProc = 'searchPresentLists'  # Stored procedure for searching present lists
            sqlArgs = [present_list_id, user_id, name, occasion, date_created]
            
            rows = db_access(sqlProc, sqlArgs)  # Query DB

            return make_response(jsonify({'present_lists': rows}), 200)

        except Exception as e:
            abort(500, message=f"Error searching present lists: {str(e)}")

class Login(Resource):
    def post(self):
        if not request.json or 'username' not in request.json or 'password' not in request.json:
            abort(400, message="Missing required fields")

        username = request.json.get('username')
        entered_password = request.json.get('password')
        date_created = request.json.get('dateCreated', None)
		

        if not is_valid_input(username) or not is_valid_input(entered_password):
            abort(400, message="Invalid characters in username or password")

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
    def get(self, present_id=None):
        if present_id is None:
            sqlProc = "getPresents"
            sqlArgs = []
        else:
            sqlProc = "getPresentByID"
            sqlArgs = [present_id]
        try:
            rows = db_access(sqlProc, sqlArgs)  # Fetch users from DB

            for row in rows:
                row.pop("password", None)  # Removes 'password' key if it exists

        except Exception as e:
            abort(500, message=str(e))  # Return server error

        return make_response(jsonify({'presents': rows}), 200)  # Return JSON response

    def put(self, present_id):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")

        # Ensure that the body of the request contains the necessary fields
        if not request.json or 'presentName' not in request.json or 'description' not in request.json or 'status' not in request.json or 'priority' not in request.json:
            abort(400, message="Missing required fields: 'presentName', 'description', 'status', 'priority'")

        present_name = request.json.get('presentName')
        description = request.json.get('description')
        status = request.json.get('status')
        priority = request.json.get('priority')

        # Update the present information in the database
        sqlProc = 'updatePresent'  # Assuming a stored procedure that updates a present
        sqlArgs = [present_name, description, status, priority, present_id]

        try:
            # Execute the stored procedure to update the present in the database
            result = db_access(sqlProc, sqlArgs)

            if result is None or result == 0:
                abort(404, message="Present not found")  # Not found

            return make_response(jsonify({"status": "success", "message": "Present updated successfully"}), 200)

        except Exception as e:
            abort(500, message="Error updating present: " + str(e))
    
    def delete(self, present_id):
        # Ensure user is logged in
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")  # 401 Unauthorized
		
        if present_id is None:
            abort(400, message="Present id is required")  # Bad request

        sqlProc = "deletePresent"  # Stored procedure to delete a user
        sqlArgs = [present_id]

        try:
            result = db_access(sqlProc, sqlArgs)  # Call DB function

            if result is None or result == 0:  # Check if user existed
                abort(404, message="Present not found")  # Not found

            return make_response(jsonify({"status": "success", "message": "Present deleted"}), 200)

        except Exception as e:
            abort(500, message=str(e))  # Server error

    def post(self):
        if 'user_id' not in session:
            abort(401, message="Unauthorized: Please log in")  # 401 Unauthorized
		
        # Ensure that the body of the request contains the necessary fields
        if not request.json or 'presentListID' not in request.json or 'presentName' not in request.json or 'description' not in request.json or 'status' not in request.json or 'priority' not in request.json:
            abort(400, message="Missing required fields: 'presentListID', 'presentName', 'description', 'status', 'priority'")

        present_list_id = request.json.get('presentListID')
        present_name = request.json.get('presentName')
        description = request.json.get('description')
        status = request.json.get('status')
        priority = request.json.get('priority')

        # Call the stored procedure to add a new present to the database
        sqlProc = 'addPresent'
        sqlArgs = [present_list_id, present_name, description, status, priority]

        try:
            # Execute the stored procedure to insert the new present
            result = db_access(sqlProc, sqlArgs)

            # If the result is not valid, we handle the error
            if result is None or result == 0:
                abort(500, message="Failed to add present")  # Server error

            return make_response(jsonify({"status": "success", "message": "Present added successfully"}), 201)

        except Exception as e:
            abort(500, message="Error adding present: " + str(e))  # Server error
    
class PresentSearch(Resource):
    def get(self):
        # Extract search parameters from the query string (optional)
        present_name = request.args.get('presentName', None)
        description = request.args.get('description', None)
        status = request.args.get('status', None)
        priority = request.args.get('priority', None)
        present_list_id = request.args.get('presentListID', None)

        # Convert status and priority to appropriate types if provided
        if status is not None:
            status = True if status.lower() == 'true' else False
        
        if priority is not None:
            priority = int(priority)
        
        if present_list_id is not None:
            present_list_id = int(present_list_id)

        # Call the stored procedure with the parameters
        sqlProc = 'searchPresents'
        sqlArgs = [present_name, description, status, priority, present_list_id]

        try:
            # Fetch the presents from the database based on the search criteria
            rows = db_access(sqlProc, sqlArgs)

            return make_response(jsonify({'presents': rows}), 200)

        except Exception as e:
            abort(500, message="Error searching presents: " + str(e))

class VerificationToken(Resource):
    def get(self, id=None):
        if not id:
            return {"error": "Missing user_id"}, 400

        return generate_verification_token(id)

class Verify(Resource):
    
    def get(self):
        user_id = request.args.get("userId", type=int)
        token = request.args.get("token")

        if not user_id or not token:
            return {"message": "Missing userId or token"}, 400

        # Verify token directly inside this method
        sqlProc = "get_verification_token"
        sqlArgs = [user_id, token]
        result = db_access(sqlProc, sqlArgs)

        if not result:
            return {"message": "Invalid or expired token"}, 400

        token_data = result[0]
        expires_at = token_data["expires_at"]

        if datetime.utcnow() > expires_at:
            return {"message": "Token has expired"}, 400

        # Mark email as verified
        db_access("mark_email_verified", [user_id])

        return {"message": "Email verified successfully!"}, 200

class SendEmail(Resource):
    def post(self):
        data = request.get_json()

        to_email = data.get("email")
        verification_link = data.get("verification_link")

        if not to_email or not verification_link:
            return {"error": "Missing email or verification_link"}, 400

        try:
            send_verification_email(to_email, verification_link)
            return {"message": "Email sent successfully!"}, 200
        except Exception as e:
            return {"error": f"Failed to send email: {str(e)}"}, 500

def generate_verification_token(user_id):
    # Create a token using the user ID and a random salt
    salt = os.urandom(16)
    token = hashlib.sha256(f"{user_id}{salt}".encode()).hexdigest()

    # Set token expiration (1 hour from now)
    expiration_time = datetime.utcnow() + timedelta(hours=1)

    sqlProc = "save_verification_token"
    sqlArgs = [user_id, token, expiration_time]

    try:
        db_access(sqlProc, sqlArgs)
    except Exception as e:
        return {"error": f"Error saving token: {e}"}

    return {"token": token, "expires_at": expiration_time.isoformat()}
 
def send_verification_email(to_email, verification_link):
    # Set up the server and login details
    smtp_server = "smtp.unb.ca"
    smtp_port = 25  # Standard SMTP port (no authentication)

    from_email = "CS3103@unb.ca"  # Your email address
    subject = "Email Verification for Present Registery"
    body = f"Please verify your email by clicking the link: {verification_link}"

    # Create the message
    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = to_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail(from_email, to_email, message.as_string())
        print("Verification email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def is_valid_email(email):
    """ Validate email format using regex """
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(email_regex, email) is not None

def is_strong_password(password):
    """ Enforce strong password: 8+ chars, uppercase, lowercase, digit, special char """
    return (
        len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in "!@#$%^&*()-_+=" for c in password)
    )

def is_valid_input(value):
    """Allow only letters, numbers, underscores, spaces, and specific special characters: +=!$#&"""
    return bool(re.fullmatch(r'[\w\s+=!$#&]+', value))  # Blocks `<script>`, `-/<>`, etc.


####################################################################################
#
# Identify/create endpoints and endpoint objects
#
api = Api(app)
api.add_resource(Login, '/Auth/Login')
api.add_resource(Logout, '/Auth/Logout')
api.add_resource(User, "/user", "/user/<int:id>")
api.add_resource(UserSearch, '/user/search')
api.add_resource(UserPresentLists, "/user/<int:id>/presentlist")
api.add_resource(PresentList, '/presentlist', "/presentlist/<int:list_id>")
api.add_resource(PresentListSearch, '/presentlist/search')
api.add_resource(Settings,"/user/update")
api.add_resource(Present, '/present', '/present/<int:present_id>')
api.add_resource(PresentSearch, '/present/search')
api.add_resource(VerificationToken, "/verification-token/<int:id>")
api.add_resource(Verify, "/verification-token/verify")
api.add_resource(SendEmail, "/send-email")
#############################################################################
if __name__ == "__main__":

	context = ('cert.pem', 'key.pem') # Identify the certificates you've generated.
	app.run(host=settings.APP_HOST, port=settings.APP_PORT, ssl_context=context,debug=settings.APP_DEBUG)
