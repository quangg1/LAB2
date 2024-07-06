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
_____________(I let Bob balance is 5000$)






