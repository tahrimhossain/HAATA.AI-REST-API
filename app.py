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
from dotenv import load_dotenv

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



api.add_resource(Register,"/register")
api.add_resource(LogIn,"/login")		

if __name__ == "__main__": 
	app.run()	
