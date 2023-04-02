from marshmallow import fields, validate,Schema

class  RegistrationFormSchema(Schema):
	email = fields.Email(required=True)
	user_name = fields.Str(required=True)
	password = fields.Str(required=True)
	date_of_birth = fields.Date(required=True)
	gender = fields.Str(validate=validate.OneOf(["male", "female", "other"]))

	
class LogInFormSchema(Schema):
	email = fields.Email(required=True)
	password = fields.Str(required=True)