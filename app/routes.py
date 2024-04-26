from flask import request, render_template
from app import app, db
from .models import User
from .auth import basic_auth, token_auth

@app.route("/")
def index():
    return render_template('index.html')

# Create User
@app.route('/users', methods=['POST'])
def create_user():
    if not request.is_json:
        return {'error':'your content-type must be application/json'}, 400
    data = request.json

    required_fields = ['username', 'email', 'password']
    missing_fields = []
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    if missing_fields:
        return {'error': f"{', '.join(missing_fields)} must be in the request body"}, 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    check_users = db.session.execute(db.select(User).where( (User.username == username) | (User.email == email) )).scalars().all()
    if check_users:
        return {'error': "A user with that user name and/or email already exists"}, 400
    
    new_user = User(username=username, email=email, password=password)

    return new_user.to_dict(), 201

@app.route('/users/me')
@token_auth.login_required
def get_me():
    user = token_auth.current_user()
    return user.to_dict()

# Edit User
@app.route('/users/<int:id>', methods=['PUT'])
@token_auth.login_required()
def edit_user(id):
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    user = db.session.get(User, id)
    if user is None:
        return {'error': f"User with ID #{id} does not exist"}, 404
    current_user = token_auth.current_user()
    if current_user is not user:
        return {'error': "You are not this User. You do not have permission to edit"}, 403
    
    data = request.json
    user.update(**data)
    return user.to_dict()



# Delete User
@app.route('/users/<int:id>', methods=['DELETE'])
@token_auth.login_required()
def delete_user(id):
    user = db.session.get(User, id)
    if user is None:
        return {'error': f"User with ID #{id} does not exist"}, 404
    current_user = token_auth.current_user()
    if current_user is not user:
        return {'error': "You are not this User. You do not have permission to delete"}, 403
    
    user.delete()
    return {'success': f"{user.username} was successfully deleted"}


@app.route('/token')
@basic_auth.login_required
def get_token():
    user = basic_auth.current_user()
    return user.get_token()

