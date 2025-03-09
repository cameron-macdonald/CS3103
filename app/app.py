#!/usr/bin/env python3
from flask import Flask, jsonify, abort, request, make_response
from flask_restful import Resource, Api
import pymysql.cursors
import json

import cgitb
import cgi
import sys
cgitb.enable()

from db_util import db_access
import settings # Our server and db settings, stored in settings.py

app = Flask(__name__, static_url_path='/static')
api = Api(app)

# Error handlers
@app.errorhandler(400) # decorators to add to 400 response
def not_found(error):
	return make_response(jsonify( { "status": "Bad request" } ), 400)

@app.errorhandler(404) # decorators to add to 404 response
def not_found(error):
	return make_response(jsonify( { "status": "Resource not found" } ), 404)

class Root(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/
	def get(self):
		sqlProc = 'getUsers'
		sqlArgs = []
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it

    # curl -i -X POST -H "Content-Type: application/json" -d '
	# {"email": "test@example.com", "first": "test1", "last":"test2", "password": "test3"}' 
	# http://cs3103.cs.unb.ca:8010/
	def post(self):
		if not request.json or not 'Email' in request.json:
			abort(400) # bad request
		# Pull the results out of the json request
		email = request.json['Email'];
		first = request.json['First'];
		last = request.json['Last'];
		password = request.json['Password'];

		sqlProc = 'addUser'
		sqlArgs = [email, first, last, password,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		uri = request.base_url+'/'+str(row[0]['LAST_INSERT_ID()'])
		return make_response(jsonify( { "uri" : uri } ), 201) # successful resource creation

api.add_resource(Root,'/')
# api.add_resource(Users, '/users')

class User(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/user/3
	def get(self, userID):
		sqlProc = 'getUserByID'
		sqlArgs = [userID,]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it

	def post(self, userID):
		if not request.json or not 'Email' in request.json:
			abort(400) # bad request
		# Pull the results out of the json request
		id = request.json['UserID'];
		email = request.json['Email'];
		first = request.json['First'];
		last = request.json['Last'];
		password = request.json['Password'];

		sqlProc = 'updateUser'
		sqlArgs = [id, email, first, last, password,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		return make_response(jsonify( { "url" : request.based_url } ), 201)

    # Example request: curl -X DELETE http://cs3103.cs.unb.ca:8010/users/80
	def delete(self, userID):
		print("UserID to delete: "+str(userID))
		sqlProc = 'deleteUser'
		sqlArgs = [userID,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		return make_response('', 204)
		# return make_response(jsonify({'users': rows}), 200)
api.add_resource(User, '/users/<int:userID>')

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
api.add_resource(OtherUser, '/users/<string:email>/<string:first>/<string:last>/<date:date>')

class Lists(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/
	def get(self):
		sqlProc = 'getLists'
		sqlArgs = []
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it

    # curl -i -X POST -H "Content-Type: application/json" -d '
	# {"name": "list1", "occasion": "new year"}' 
	# http://cs3103.cs.unb.ca:8010/presentLists
	def post(self):
		if not request.json or not 'presentName' in request.json:
			abort(400) # bad request
		# Pull the results out of the json request
		name = request.json['name'];
		occasion = request.json['occasion'];

		sqlProc = 'addList'
		sqlArgs = [name, occasion,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		uri = request.base_url+'/'+str(row[0]['LAST_INSERT_ID()'])
		return make_response(jsonify( { "uri" : uri } ), 201) # successful resource creation
api.add_resource(Lists,'/presentLists')

class List(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/presentLists/3
	def get(self, listID):
		sqlProc = 'getListByID'
		sqlArgs = [listID,]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it

	def post(self, listID):
		if not request.json or not 'name' in request.json:
			abort(400) # bad request
		# Pull the results out of the json request
		name = request.json['name'];
		occasion = request.json['occasion'];

		sqlProc = 'updateList'
		sqlArgs = [listID, name, occasion,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		return make_response(jsonify( { "url" : request.based_url } ), 201)

    # Example request: curl -X DELETE http://cs3103.cs.unb.ca:8010/presentLists/80
	def delete(self, listID):
		print("ListID to delete: "+str(listID))
		sqlProc = 'deleteList'
		sqlArgs = [listID,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		return make_response('', 204)
		# return make_response(jsonify({'users': rows}), 200)
api.add_resource(List, '/presentLists/<int:listID>')

class ListByUser(Resource):
	def get(self, userID, listID):
		sqlProc = 'getListByUserID'
		sqlArgs = [listID, userID, ]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200)
api.add_resource(ListByUser, 'users/<int:usersID>/presentLists/<int:listID>')

class OtherList(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/presentLists/name/occasion/
	def get(self, name, occasion):
		sqlProc = 'getListsBy'
		sqlArgs = [name, occasion,]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it	
api.add_resource(OtherList, '/users/<string:name>/<string:occasion>/')

class Presents(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/
	def get(self):
		sqlProc = 'getPresents'
		sqlArgs = []
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it

    # curl -i -X POST -H "Content-Type: application/json" -d '
	# {"presentName": "p1", "description": "sample", "status":"1", "priority": "1"}' 
	# http://cs3103.cs.unb.ca:8010/presents
	def post(self):
		if not request.json or not 'presentName' in request.json:
			abort(400) # bad request
		# Pull the results out of the json request
		presentName = request.json['presentName'];
		description = request.json['description'];
		status = request.json['status'];
		priority = request.json['priority'];

		sqlProc = 'addPresent'
		sqlArgs = [presentName, description, status, priority,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		uri = request.base_url+'/'+str(row[0]['LAST_INSERT_ID()'])
		return make_response(jsonify( { "uri" : uri } ), 201) # successful resource creation
api.add_resource(Presents,'/presents')

class Present(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/presents/3
	def get(self, presentID):
		sqlProc = 'getPresentByID'
		sqlArgs = [presentID,]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it

	def post(self, presentID):
		if not request.json or not 'presentName' in request.json:
			abort(400) # bad request
		# Pull the results out of the json request
		listId = request.json['listID'];
		presentName = request.json['presentName'];
		description = request.json['description'];
		status = request.json['status'];
		priority = request.json['priority'];

		sqlProc = 'updatePresent'
		sqlArgs = [presentID, listId, presentName, description, status, priority,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		return make_response(jsonify( { "url" : request.based_url } ), 201)

    # Example request: curl -X DELETE http://cs3103.cs.unb.ca:8010/presents/80
	def delete(self, presentID):
		print("PresentID to delete: "+str(presentID))
		sqlProc = 'deletePresent'
		sqlArgs = [presentID,]
		try:
			row = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e)
		return make_response('', 204)
		# return make_response(jsonify({'users': rows}), 200)
api.add_resource(Present, '/presents/<int:presentID>')

class PresentByUser(Resource):
	def get(self, userID, presentID):
		sqlProc = 'getPresentByUserID'
		sqlArgs = [presentID, userID, ]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200)
api.add_resource(PresentByUser, 'users/<int:usersID>/presents/<int:presentID>')

class OtherPresent(Resource):
	# Example request: curl http://cs3103.cs.unb.ca:8010/presents/presentName/Description/Status/Priority
	def get(self, presentName, description, status, priority):
		sqlProc = 'getPresentsBy'
		sqlArgs = [presentName, description, status, priority,]
		try:
			rows = db_access(sqlProc, sqlArgs)
		except Exception as e:
			abort(500, message = e) # server error
		return make_response(jsonify({'users': rows}), 200) # turn set into json and return it	
api.add_resource(OtherPresent, '/users/<string:presentName>/<string:description>/<int:status/<int:priority>')

if __name__ == "__main__":
#    app.run(host="cs3103.cs.unb.ca", port=xxxx, debug=True)
	app.run(host=settings.APP_HOST, port=settings.APP_PORT, debug=settings.APP_DEBUG)
