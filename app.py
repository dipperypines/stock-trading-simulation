import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    rows = db.execute("SELECT * FROM portfolio WHERE user_id = ?", session.get("user_id"))
    stock_info = []
    for row in rows:
        # Defining key in every dictionary in stock_info list
        symbol = row["stock"]
        quantity = row["quantity"]

        x = lookup(symbol)
        price = x["price"]
        total_value = price * quantity

        # Appending the values to every key in the dictionary
        stock_info.append(
            {
                "symbol": symbol,
                "quantity": quantity,
                "price": price,
                "total_value": total_value
            }
        )

    # Pass the list of dictionary into index.html
    # Pass the cash balance to index.html
    cash_balance = db.execute("SELECT cash FROM users WHERE id = ?", session.get("user_id"))
    # Calculate the grand total
    grand_total = 0
    for stock in stock_info:
        grand_total += stock["price"] * stock["quantity"]
    grand_total += cash_balance[0]["cash"]

    return render_template("index.html", stock_info=stock_info, cash_balance=int(cash_balance[0]["cash"]), grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # If requested via POST
    if request.method == "POST":
        # If input is blank
        if not request.form.get("symbol"):
            return apology("Must provide a symbol", 400)

        # If symbol does not exist
        stock = lookup(request.form.get("symbol"))
        if stock is None:
            return apology("Symbol could not be found", 400)

        # If shares entered not a positive integer
        shares_str = request.form.get("shares")
        if not shares_str.isdigit() or int(shares_str) <= 0:
            return apology("Shares must be a positive integer", 400)

        # If shares entered is a positive integer
        symbol = str(stock["symbol"])
        price = stock["price"]
        user = int(session.get("user_id"))
        shares = int(shares_str)
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        order_type = "Buy"
        print("CHECK CHECK CHECK:", symbol, price, user, shares, time)
        db.execute("""
                   INSERT INTO orders (user_id, symbol, price, shares, time, order_type)
                   VALUES (?, ?, ?, ?, ?, ?)
                   """,
                   user, symbol, price, shares, time, order_type
                   )

        # Check if the user has sufficient funds
        fund = db.execute("SELECT cash FROM users WHERE id = ?", user)
        if fund[0]["cash"] < shares * price:
            return apology("Insufficient funds for transaction", 400)

        # If user has sufficient funds, deduct money from the user
        else:
            fund[0]["cash"] = fund[0]["cash"] - (shares * price)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", fund[0]["cash"], user)

            # Check if the user already has shares of the stock
            check = db.execute("SELECT stock FROM portfolio WHERE stock = ? AND user_id = ?", symbol, user)

            # If user does not have shares of the stock, create a new row
            if len(check) == 0:
                db.execute("INSERT INTO portfolio (user_id, stock, quantity) VALUES (?, ?, ?)", user, symbol, shares)

            # If user has shares of the stock, update existing row
            else:
                # Get the current number of shares the user has for the stock
                current_share = db.execute("SELECT quantity FROM portfolio WHERE user_id = ? AND stock = ?", user, symbol)
                # Add the shares the user bought with current number of shares
                new_shares = current_share[0]['quantity'] + shares
                db.execute("UPDATE portfolio SET quantity = ? WHERE user_id = ? AND stock = ?", new_shares, user, symbol)

        # Redirect user to home page
        return redirect("/")

    # If requested via GET
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Obtain stock info from ORDERS table
    stock_info = db.execute("SELECT * FROM orders")

    # Render template, passing in stock_info
    return render_template("history.html", stock_info=stock_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # If requested via POST
    if request.method == "POST":
        # If symbol not provided
        if not request.form.get("symbol"):
            return apology("Must provide a symbol", 400)

        # If symbol not found
        stock = lookup(request.form.get("symbol"))
        print(stock)
        if stock is None:
            return apology("Symbol could not be found", 400)

        # If symbol is found
        return render_template("quoted.html", stock=stock)

    # If requested via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # If requested by POST
    if request.method == "POST":

        # If username and/or password and/or confirmation not provided
        if not request.form.get("username") or not request.form.get("password") or not request.form.get("confirmation"):
            flash("Must provide a username, password, and confirmation password", "error")
            return apology("Must provide a username, password, and confirmation password", 400)

        # If username already exists
        rows = db.execute("SELECT * FROM users where username = ?", request.form.get("username"))
        if len(rows) != 0:
            flash("Username already exists", "error")
            return apology("Username already exists", 400)

        # If password and confirmation do not match
        if request.form.get("password") != request.form.get("confirmation"):
            flash("Password and confirmation password do not match", "error")
            return apology("Password and confirmation password do not match", 400)

        # Insert the user data into users table
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        return redirect("/login", 200)

    # If requested by GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # If requested by POST
    if request.method == "POST":

        # If user doesn't input a stock symbol or number of shares
        if not request.form.get("symbol") or not request.form.get("shares"):
            return apology("Must provide a stock name and number of shares", 400)

        # If user doesn't own the stock
        owned = False
        stocks = db.execute("SELECT stock FROM portfolio WHERE user_id = ?", session.get("user_id"))
        for stock in stocks:
            if stock['stock'] == request.form.get("symbol"):
                owned = True
        if not owned:
            return apology("Please provide a stock that you own", 400)

        # If user doesn't input a positive integer
        stock_info = lookup(request.form.get("symbol"))
        user = session.get("user_id")
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        price = stock_info["price"]
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        order_type = "Sell"
        if not shares.isdigit() or int(shares) <= 0:
            return apology("Please provide a positive integer for the number of shares", 400)

        # If the user has insufficient stocks
        quantity = db.execute("SELECT quantity FROM portfolio WHERE user_id = ? AND stock = ?", user, symbol)
        if int(shares) > quantity[0]["quantity"]:
            return apology("You don't own that many stocks", 400)

        # Deduct the shares that the user owns
        old_shares = db.execute("SELECT quantity FROM portfolio WHERE user_id = ? AND stock = ?", user, symbol)
        new_shares = old_shares[0]["quantity"] - int(shares)
        db.execute("UPDATE portfolio SET quantity = ? WHERE user_id = ? AND stock = ?", new_shares, user, symbol)

        # Add sold stocks into transaction history
        db.execute("""INSERT INTO orders
                   (user_id, symbol, price, shares, time, order_type)
                   VALUES
                   (?, ?, ?, ?, ?, ?)
                   """,
                   user, symbol, price, shares, time, order_type)

        # Add cash to the user
        revenue = price * int(shares)
        current_balance = db.execute("SELECT cash FROM users WHERE id = ?", user)
        new_balance = revenue + current_balance[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, user)

        # Return to the homepage
        return redirect("/")

    # If requested by GET
    else:
        rows = db.execute("SELECT stock FROM portfolio WHERE user_id = ?", session.get("user_id"))
        return render_template("sell.html", rows=rows)
