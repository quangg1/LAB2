# LAB2
# 22110064, Nguyễn Minh Phú Quang
# ____________________ CSRF Attack Lab _________________

# What is CSRF Attack?
## *An attack that forces authenticated users to submit a request to a Web application against which they are currently authenticated.
CODE:

````python
    from flask import Flask, request, make_response, render_template_string
import json

app = Flask(__name__)

# Simulate a database
user_accounts = {
    'alice': {'balance': 10000, 'password': 'alice'},
    'attacker': {'balance': 0, 'password': '12345'},
    'bob': {'balance': 10000, 'password': 'bob'},
}

@app.route('/')
def home():
    return "Welcome to the Bank"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in user_accounts and user_accounts[username]['password'] == password:
            resp = make_response(f"Logged in as {username}")
            resp.set_cookie('user_session', json.dumps({'username': username}))
            return resp
        else:
            return "Invalid credentials", 401
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Log In">
        </form>
    '''

@app.route('/logout')
def logout():
    resp = make_response("Logged out")
    resp.set_cookie('user_session', '', expires=0)
    return resp

@app.route('/balance')
def balance():
    session_data = get_session_data()
    if not session_data:
        return "Please log in first", 401
    username = session_data['username']
    balance = user_accounts[username]['balance']
    return f"Your balance is ${balance}"

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    session_data = get_session_data()
    if not session_data:
        return "Please log in first", 401
    
    if request.method == 'POST':
        from_account = session_data['username']
        to_account = request.form['to']
        amount = int(request.form['amount'])
        
        if to_account not in user_accounts:
            return "Recipient account does not exist", 400
        if amount <= 0:
            return "Invalid amount", 400
        if user_accounts[from_account]['balance'] < amount:
            return "Insufficient funds", 400
        
        # Perform transfer
        user_accounts[from_account]['balance'] -= amount
        user_accounts[to_account]['balance'] += amount
        
        return f"Transferred ${amount} to account {to_account}"
    
    # GET request: show transfer form
    return '''
        <form method="post">
            To account: <input type="text" name="to"><br>
            Amount: <input type="number" name="amount"><br>
            <input type="submit" value="Transfer">
        </form>
    '''

def get_session_data():
    session_cookie = request.cookies.get('user_session')
    if session_cookie:
        return json.loads(session_cookie)
    return None

if __name__ == '__main__':
    app.run(debug=True)
````

## Task 1: Normal transaction with CRSF vulnerability
* Login as Alice
````python
PS C:\Users\pc\Downloads\LAB2> python target.py -m flask run
````
The result is:
````python
 * Serving Flask app 'target'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
````
![Welcome](https://github.com/quangg1/LAB2/assets/89339772/97f23a54-9692-4dc9-a588-6dbcec5a4f07)
Now as we has the link of the local host, we can login in [http://localhost:5000/login](http://localhost:5000/login)
And when the page pop up, login as Alice with her username and password as the code above given :

![image](https://github.com/quangg1/LAB2/assets/89339772/9550a724-7598-4c21-a1d8-32c420d9d687)

![image](https://github.com/quangg1/LAB2/assets/89339772/d7cabcee-3eb7-4742-946d-6a8c89c60f23)

* Perform a transaction
1. Navigate to the transfer page [(http://localhost:5000/transfer).](http://localhost:5000/transfer) .
2. Fill out the transfer form to send money to Bob:
To Account: bob
Amount: Enter a valid amount that Alice can afford ( <= balance= 1000).

![image](https://github.com/quangg1/LAB2/assets/89339772/c59e4ae4-66ce-4178-a33a-ff462e52042a)

*Transfer Money Illegitimately (CSRF Exploit)
- As first, let's transfer to Bob 5000$ to check if the transfermation is completed.

![image](https://github.com/quangg1/LAB2/assets/89339772/e98be0d3-c4c8-4e11-88b9-d5bc440d0343)

![image](https://github.com/quangg1/LAB2/assets/89339772/ef765b0e-24d8-4a87-9b74-f5cbb5f87c08)

![image](https://github.com/quangg1/LAB2/assets/89339772/d8467fb5-772a-4cc5-8168-afbcd5f825f9)

-Next, check Bob balance, by logging out again and logging in with bob acoount and get to the link  [(http://localhost:5000/balance).](http://localhost:5000/balance) if Bob's balance changed.

![image](https://github.com/quangg1/LAB2/assets/89339772/e36339b5-3b21-4b69-ace7-d50d7a8a7e68)
_____________ (I let Bob balance is 5000$)
Now we wil change the default html page of transfer::

````css
         return '''
        <form method="post">
            To account: <input type="text" name="to"><br>
            Amount: <input type="number" name="amount"><br>
            <input type="submit" value="Transfer">
        </form>
    '''
````
to the html page that will transfer the money to the attacker:
````css
<html>
<body onload="document.forms[0].submit()">
    <form action="http://localhost:5000/transfer" method="post">
        <input type="hidden" name="to" value="attacker">
        <input type="hidden" name="amount" value="5000">
        
    </form>
</body>
</html>
````
*- Code explanation: The HTML code provided is a simple form that automatically submits when the page is loaded. This form is used to demonstrate a CSRF attack, where an unsuspecting user (Alice) is tricked into performing an unauthorized action (such as transferring money) without their knowledge.
  - As soon as Alice click on the transfer link, the above html page will summit immediately:

    ````css
           <body onload="document.forms[0].submit()">
    ````

  - The form contains hidden input fields to specify the recipient account (to set to "attacker") and the amount (amount set to "5000").
   
    ````css
            <form action="http://localhost:5000/transfer" method="post">
                   <input type="hidden" name="to" value="attacker">
                   <input type="hidden" name="amount" value="5000">
            </form>
    ````
   - And the result is:

![image](https://github.com/quangg1/LAB2/assets/89339772/23019046-882f-4e20-9bb0-e2cb0f1daa63)
 
   - Login as the attacker to check the balance: 

![image](https://github.com/quangg1/LAB2/assets/89339772/865aa842-5a0e-4472-ab09-d43b840150f2)

## Task 2: CSRF Countermeasure implementation
### 2.1 Solution 1: Using CSRF token
- CSRF (Cross-Site Request Forgery) tokens are used to protect web applications from CSRF attacks. A CSRF attack tricks a user into performing an unwanted action on a web application where they are authenticated. To prevent this, CSRF tokens are used to ensure that the actions are genuinely initiated by the user.

- How CSRF Tokens Work
  -Token Generation:

  -When a user visits a page with a form, the server generates a unique token for the user session.
This token is stored both in the user's session (server-side) and included in the form (client-side).
Token Submission:

  -When the user submits the form, the token is sent along with the form data.
Token Verification:

  - The server receives the form data and the token.
    - It verifies that the token from the form matches the token stored in the user's session.
    - If the tokens match, the request is considered legitimate, and the action is performed.
    - If the tokens do not match, the request is rejected as a potential CSRF attack.

 **Uploading full new update code with CSRF token:**
````python
 from flask import Flask, request, make_response, render_template_string, session, redirect, url_for
import os
import json
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Set a secret key for the app
app.secret_key = 'anothersecretkey'  # Another secret key for session management

# Simulate a database
user_accounts = {
    'alice': {'balance': 10000, 'password': 'alice'},
    'attacker': {'balance': 0, 'password': '12345'},
    'bob': {'balance': 10000, 'password': 'bob'},
}

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    return session['_csrf_token']

def verify_csrf_token(token):
    return token == session.get('_csrf_token')

@app.before_request
def before_request():
    generate_csrf_token()

@app.context_processor
def csrf_token_processor():
    return dict(csrf_token=generate_csrf_token)

@app.route('/')
def home():
    return "Welcome to the Bank"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form.get('_csrf_token')
        if not verify_csrf_token(token):
            return "CSRF token is invalid", 400

        username = request.form['username']
        password = request.form['password']
        if username in user_accounts and user_accounts[username]['password'] == password:
            resp = make_response(f"Logged in as {username}")
            resp.set_cookie('user_session', json.dumps({'username': username}))
            return resp
        else:
            return "Invalid credentials", 401

    csrf_token = generate_csrf_token()
    return render_template_string('''
        <form method="post">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Log In">
        </form>
    ''', csrf_token=csrf_token)

@app.route('/logout')
def logout():
    resp = make_response("Logged out")
    resp.set_cookie('user_session', '', expires=0)
    return resp

@app.route('/balance')
def balance():
    session_data = get_session_data()
    if not session_data:
        return "Please log in first", 401
    username = session_data['username']
    balance = user_accounts[username]['balance']
    return f"Your balance is ${balance}"

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    session_data = get_session_data()
    if not session_data:
        return "Please log in first", 401

    if request.method == 'POST':
        token = request.form.get('_csrf_token')
        if not verify_csrf_token(token):
            return "CSRF token is invalid", 400

        from_account = session_data['username']
        to_account = request.form['to']
        amount = int(request.form['amount'])

        if to_account not in user_accounts:
            return "Recipient account does not exist", 400
        if amount <= 0:
            return "Invalid amount", 400
        if user_accounts[from_account]['balance'] < amount:
            return "Insufficient funds", 400

        # Perform transfer
        user_accounts[from_account]['balance'] -= amount
        user_accounts[to_account]['balance'] += amount

        return f"Transferred ${amount} to account {to_account}"

    csrf_token = generate_csrf_token()
    return render_template_string('''
        <form method="post">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
            To account: <input type="text" name="to"><br>
            Amount: <input type="number" name="amount"><br>
            <input type="submit" value="Transfer">
        </form>
    ''', csrf_token=csrf_token)

def get_session_data():
    session_cookie = request.cookies.get('user_session')
    if session_cookie:
        return json.loads(session_cookie)
    return None

if __name__ == '__main__':
    app.run(debug=True)
````

 **_CODE EXPLAINATION_**
 - Configure a secret key used for generating CSRF tokens:
````python
app.secret_key = 'anothersecretkey'  # Another secret key for session management
````
 - Create functions to generate and verify CSRF tokens:
````python
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    return session['_csrf_token']

def verify_csrf_token(token):
    return token == session.get('_csrf_token')
````
 - Modify the login and transfer forms to include a CSRF token.
  - Before rendering the form, the generate_csrf_token function is called to ensure a CSRF token is available in the session.
  - The token is included in the form as a hidden input field (<input type="hidden" name="_csrf_token" value="{{ csrf_token }}">).
  - Verify CSRF Token on Form Submission
   - When the form is submitted, the server retrieves the _csrf_token from the form data.
   - It calls verify_csrf_token to check if the token matches the one stored in the session.
   - If the tokens do not match, the request is rejected with a "CSRF token is invalid" error.
   - If the token is valid, the server proceeds with processing the form data (e.g., performing the transfer).

    ````python
    @app.route('/transfer', methods=['GET', 'POST'])
    def transfer():
    session_data = get_session_data()
    if not session_data:
        return "Please log in first", 401

    if request.method == 'POST':
        token = request.form.get('_csrf_token')
        if not verify_csrf_token(token):
            return "CSRF token is invalid", 400

        from_account = session_data['username']
        to_account = request.form['to']
        amount = int(request.form['amount'])

        if to_account not in user_accounts:
            return "Recipient account does not exist", 400
        if amount <= 0:
            return "Invalid amount", 400
        if user_accounts[from_account]['balance'] < amount:
            return "Insufficient funds", 400

        # Perform transfer
        user_accounts[from_account]['balance'] -= amount
        user_accounts[to_account]['balance'] += amount

        return f"Transferred ${amount} to account {to_account}"

 - Set Up the CSRF Token Generation in the Template:
   - Ensure the CSRF token is available in the template context:
````python
@app.before_request
def before_request():
    generate_csrf_token()

@app.context_processor
def csrf_token_processor():
    return dict(csrf_token=generate_csrf_token)
````
 - Help Function to Get Session Data:
  - Define the function to get session data:
````python
def get_session_data():
    session_cookie = request.cookies.get('user_session')
    if session_cookie:
        return json.loads(session_cookie)
    return None
````
*Now when i click on the transfer link which has been attacked,log in as Alice,  this is what happen*
![image](https://github.com/quangg1/LAB2/assets/89339772/f22a92b5-d83a-4f8f-aec3-7678cba02672)

It is protecting Alice from the attack by the attacker.





