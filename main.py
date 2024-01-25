from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
import jwt
import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb+srv://makerstest:makerspass@makers.x41mhwn.mongodb.net/users"

mongo = PyMongo(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'ASJKLA123/&%//kjkshda'

# Decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403

        return f(*args, **kwargs)

    return decorated

# Registration route
@app.route('/register', methods=['POST'])
def register():
    users = mongo.db.users
    email = request.json['email']
    password = request.json['password']

    if users.find_one({'email': email}):
        return jsonify({'message': 'User already exists!'})

    hashed_password = generate_password_hash(password)
    users.insert_one({'email': email, 'password': hashed_password})

    return jsonify({'message': 'Registered successfully'})

# Login route
@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    email = request.json['email']
    password = request.json['password']
    user = users.find_one({'email': email})

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid email or password'})

    token = jwt.encode({'user': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
    
    # Return the token directly without decoding
    return jsonify({'token': token})

@app.route('/secure-route')
@token_required
def secure_route():
    return jsonify({'message': 'This is only available with a valid token'})

if __name__ == '__main__':
    app.run(debug=True, port=8000)