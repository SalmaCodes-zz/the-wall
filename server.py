from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import md5, re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = 'SuperSecretKey'
mysql = MySQLConnector(app,'walldb')


@app.route('/')
def index():
    return render_template('index.html') # pass data to our template


@app.route('/wall')
def wall():
    # Get user id from session
    id = session['user_id']

    # Get user info by id from database
    query = "SELECT * FROM users WHERE id = {}".format(id)       
    user_data = mysql.query_db(query) 

    # Get all messages
    query = "SELECT messages.id, "
    query += "  CONCAT_WS(' ', users.first_name, users.last_name) AS user_name, "
    query += "  DATE_FORMAT(messages.created_at, '%M %D, %Y %H:%m:%s') AS time, messages.message "
    query += "FROM messages "
    query += "JOIN users "
    query += "ON users.id = messages.user_id "
    query += "ORDER BY messages.created_at DESC"
    messages = mysql.query_db(query)

    # Get all the comments
    query = "SELECT comments.message_id AS parent_id, "
    query += "  CONCAT_WS(' ', users.first_name, users.last_name) AS user_name, "
    query += "  DATE_FORMAT(comments.created_at, '%M %D, %Y %H:%m:%s') AS time, comments.comment "
    query += "FROM comments "
    query += "JOIN messages "
    query += "ON  messages.id = comments.message_id "
    query += "JOIN users "
    query += "ON users.id = comments.user_id "
    query += "ORDER BY comments.created_at ASC"
    comments = mysql.query_db(query)
    return render_template('wall.html', user_info=user_data, all_messages=messages, all_comments=comments)


# Creates a new message and redirects to the wall.
@app.route('/post', methods=['POST'])
def create():
    # Insert message into the messages table.
    if (request.form['type'] == 'message'):
        query = "INSERT INTO messages (user_id, message, created_at, updated_at) "
        query += "VALUES (:user_id, :message, NOW(), NOW())"
        data = {
            'user_id': session['user_id'],
            'message': request.form['text']
        }
        mysql.query_db(query, data)

    # If the message is a comment, insert comment record into the comments table.
    elif (request.form['type'] == 'comment'):
        query = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) "
        query += "VALUES (:message_id, :user_id, :comment, NOW(), NOW())"
        data = {
            'message_id': request.form['parent'],
            'user_id': session['user_id'],
            'comment': request.form['text']
        }
        mysql.query_db(query, data)
    
    return redirect('/wall')


# Processes both login and registration forms and redirects to the wall.
@app.route('/process', methods=['POST'])
def process():
    is_valid = True
    ftype = request.form['type']
    # Registration form
    if (ftype == 'register'):
        # Validations:
        # 1. First Name - letters only, at least 2 character
        # 2. Last Name - letters only, at least 2 character
        # 3. Email - Valid Email format
        # 4. Password - at least 8 characters
        # 5. Password Confirmation - matches password
        fname = request.form['first_name']
        lname = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        password_confirmation = request.form['password_confirmation']
        if len(email) < 1:
            flash("Email cannot be empty!")
            is_valid = False
        elif not EMAIL_REGEX.match(request.form['email']):
            flash("Invalid Email Address!")
            is_valid = False
        if len(fname) < 2:
            flash("First Name must be at least 2 characters.")
            is_valid = False
        if not fname.isalpha():
            flash("First Name must be letters only.")
            is_valid = False
        if len(lname) < 2:
            flash("Last Name must be at least 2 characters.")
            is_valid = False
        if not lname.isalpha():
            flash("Last Name must be letters only.")
            is_valid = False
        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            is_valid = False
        if password != password_confirmation:
            flash("Password Confirmation must match Password.")
            is_valid = False

        # If the data is valid, we insert new user into the table    
        if (is_valid):
            # Insert into the table
            query = "INSERT INTO users (first_name, last_name, email, password) VALUES (:first_name, :last_name, :email, :password)"
            # encrypt the password we provided as 32 character string
            hashed_password = md5.new(password).hexdigest()
            data = {
                'first_name': fname,
                'last_name': lname,
                'email': email,
                'password': hashed_password
            }
            result = mysql.query_db(query, data)
            session['user_id'] = result # TODO: get row id from query result;
            return redirect('/wall')

    # Login form
    elif (ftype == 'login'):
        email = request.form['login_email']
        password = request.form['login_password']

        # Validate that the email field is not empty.
        if len(email) < 1:
            flash("Email cannot be empty!")
            is_valid = False 
        elif not EMAIL_REGEX.match(email):
            flash("Invalid Email Address!")
            is_valid = False

        # Check that the user is registered.
        query = "SELECT * FROM users WHERE email = '{}'".format(email)
        data = mysql.query_db(query)
        if (len(data) < 1):
            flash("Email does not exist. Register first!")
            is_valid = False
        # Make sure the password matches
        elif (data[0]['password'] != md5.new(password).hexdigest()):
            flash("Incorrect password. Try again!")
            is_valid = False
        
        if (is_valid):
            session['user_id'] = data[0]['id']
            return redirect('/wall')

    return redirect('/')


app.run(debug=True)