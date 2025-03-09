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