from flask import Flask,request
from flask_cors import CORS
from flask_restful import Api,Resource,abort
from pymongo import MongoClient
from bson import ObjectId
from bson import json_util
import datetime
import json
import os
import form_schema
import bcrypt
import jwt
from jwt.exceptions import InvalidSignatureError,ExpiredSignatureError
from werkzeug.exceptions import Unauthorized,BadRequest
from dotenv import load_dotenv
import gpxpy

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
api = Api(app)

load_dotenv()

access_token_secret_key = os.environ.get('ACCESS_TOKEN_SECRET_KEY')
mongo_url = os.environ.get('MONGO_URL')
client = MongoClient(mongo_url)
database = client["haata_ai_database"]



registration_form_schema = form_schema.RegistrationFormSchema()
log_in_form_schema = form_schema.LogInFormSchema()

class Register(Resource):
	
	def post(self):
		data = request.json
		if registration_form_schema.validate(data):
			print(registration_form_schema.validate(data))
			abort(400,message="Invalid input")
		user_info = database.users.find_one({"email":data["email"]})
		if user_info == None:
			data["password"] = bcrypt.hashpw(data["password"].encode("utf-8"),bcrypt.gensalt())
			database.users.insert_one(data)
			token = jwt.encode({"email":data['email'],"exp":datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=6)},access_token_secret_key,algorithm = "HS256")
			return {"access_token":token}
		else:
			abort(409,message = "This email is already in use")



class LogIn(Resource):

	def post(self):
		data = request.json
		if log_in_form_schema.validate(data):
			abort(400,message="Invalid input")
		user_info = database.users.find_one({"email":data["email"]})				
		if user_info == None:
			abort(401,message = "User with this email does not exist")
		else:
			if bcrypt.checkpw(data["password"].encode("utf-8"),user_info["password"]):
				token = jwt.encode({"email":data['email'],"exp":datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(hours=6)},access_token_secret_key,algorithm = "HS256")
				return {"access_token":token}
			else:	
				abort(401,message="Wrong password")	

class WalkabilityDataEntry(Resource):
	def post(self):
		try:
			sent_files = request.files
			
			if len(dict(sent_files)) == 0:
				raise("No file attached")
			elif len(dict(sent_files)) > 1:
				raise("Too many files attached")
			
			if 'path' not in dict(sent_files):
				raise BadRequest("The key of the sent file must be path")	
		
			if sent_files['path'].filename.split('.')[1] != "gpx":
				raise BadRequest("Unsopported file type")
			
			gpx_file = sent_files['path'].read()

			form_data = request.form

			if len(dict(form_data)) == 0:
				raise BadRequest("Rating not provided")

			if'path_rating' not in dict(form_data):
				raise BadRequest("The key of the sent file must be path_rating")

			path_rating = form_data.to_dict(flat=True)['path_rating']
			path_rating = json.loads(path_rating)
			
			#validate path_rating using schema here

			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			
			user_info = database.users.find_one({"email":payload["email"]})

			if user_info == None:
				abort(401,message = "User with this email does not exist")

			gpx = gpxpy.parse(gpx_file)
			coordinates = []

			for track in gpx.tracks:
				for segment in track.segments:
					for point in segment.points:
						coordinates.append({"latitude":point.latitude,"longitude":point.longitude,"elavation":point.elevation,"time":point.time.strftime("%Y-%m-%d")})

			database.paths.insert_one({"coordinates":coordinates,"rating":path_rating['rating'],"permanent_obstacle_count":path_rating['permanent_obstacle_count'],"temporary_obstacle_count":path_rating['temporary_obstacle_count'],"hazard":path_rating['hazard'],"cleanliness":path_rating['cleanliness'],"safety":path_rating['safety'],"congestion":path_rating['congestion'],"width":path_rating['width'],"user_id":str(user_info['_id'])})			
		except BadRequest as e:
			abort(400,message=e.description)
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			print(e)
			abort(400,message="Could not process request")

class CreatedPaths(Resource):
	def get(self):
		try:
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			
			user_info = database.users.find_one({"email":payload["email"]})

			if user_info == None:
				abort(401,message = "User with this email does not exist")

			documents = database.paths.find({"user_id":str(user_info["_id"])})
			paths = []
			for document in documents:
				document.pop("_id")
				document.pop("user_id")
				paths.append(document)
				break

			return {"paths":paths}	
			
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			abort(400,message="Could not process request")


class UserInfo(Resource):
	def get(self):
		try:
			token = request.headers.get('Authorization')
			if token == None:
				raise Unauthorized("Authorization required")
			payload = jwt.decode(token,key=access_token_secret_key,verify=True,algorithms = ["HS256"])
			
			user_info = database.users.find_one({"email":payload["email"]})

			if user_info == None:
				abort(401,message = "User with this email does not exist")

			user_info.pop("_id")
			user_info.pop("password")

			return user_info	
		except Unauthorized	as e:
			abort(401,message=e.description)
		except InvalidSignatureError as e:
			abort(498,message="Invalid token")
		except ExpiredSignatureError as e:
			abort(401,message='Token expired')		
		except Exception as e:
			abort(400,message="Could not process request")

api.add_resource(Register,"/register")
api.add_resource(LogIn,"/login")
api.add_resource(WalkabilityDataEntry,"/walkabilitydataentry")
api.add_resource(UserInfo,"/userinfo")		
api.add_resource(CreatedPaths,"/createdpaths")		

if __name__ == "__main__": 
	app.run()	
