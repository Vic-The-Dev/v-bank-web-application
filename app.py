import os
import re
import secrets

import bcrypt
import psycopg

from psycopg.rows import dict_row
from flask import (Flask, render_template, redirect, url_for, request, flash, session)
from dotenv import load_dotenv
from decimal import Decimal, InvalidOperation

load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing from the environment.")

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing from the environment.")


def get_db_connection():
    return psycopg.connect(
        DATABASE_URL,
        connect_timeout=5,
        row_factory=dict_row
    )


def generate_account_number():
    return str(secrets.randbelow(9000000000) + 1000000000)

def parse_amount(value):
    try:
        amount = Decimal(value)
    except (InvalidOperation, TypeError):
        return None

    if not amount.is_finite() or amount <= 0:
        return None

    if amount.as_tuple().exponent < -2:
        return None

    if amount > Decimal("9999999999999.99"):
        return None

    return amount


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        password_pattern = r"[A-Za-z][A-Za-z0-9_#]{5,11}"

        f_name = request.form.get("first_name", "").strip()
        l_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        password = request.form.get("password", "")
        confirm_password = request.form.get("check_password", "")

        pin = request.form.get("pin", "").strip()
        confirm_pin = request.form.get("confirm_pin", "").strip()

        if not all([
            f_name,
            l_name,
            email,
            password,
            confirm_password,
            pin,
            confirm_pin
        ]):
            flash("Fill in all required fields.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(password_pattern, password):
            flash(
                "Password must be 6-12 characters and start with a letter.",
                "error"
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(r"\d{4}", pin):
            flash("PIN must contain exactly 4 digits.", "error")
            return redirect(url_for("register"))

        if pin != confirm_pin:
            flash("PINs do not match. Please try again.", "error")
            return redirect(url_for("register"))

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        hashed_pin = bcrypt.hashpw(
            pin.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        account_number = generate_account_number()

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO customers
                        (first_name, last_name, email, phone, hashed_password)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING customer_id
                        """,
                        (
                            f_name,
                            l_name,
                            email,
                            phone or None,
                            hashed_password
                        )
                    )

                    customer = cur.fetchone()
                    customer_id = customer["customer_id"]

                    cur.execute(
                        """
                        INSERT INTO accounts
                        (customer_id, account_number, balance, pin_hash)
                        VALUES (%s, %s, %s, %s)
                        RETURNING account_id
                        """,
                        (
                            customer_id,
                            account_number,
                            1000,
                            hashed_pin
                        )
                    )

                    account = cur.fetchone()
                    account_id = account["account_id"]

                    cur.execute(
                        """
                        INSERT INTO transactions
                        (account_id, transaction_type, amount, recipient_account_id)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            account_id,
                            "ACCOUNT_BONUS",
                            1000,
                            None
                        )
                    )

        except psycopg.errors.UniqueViolation:
            flash(
                "An account with these details already exists. Please check your email or try again.",
                "error"
            )
            return redirect(url_for("register"))

        except psycopg.Error:
            app.logger.exception("Database error while registering user")
            flash("We couldn't register your account. Please try again.", "error")
            return redirect(url_for("register"))

        flash("Account created successfully. Login to continue.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT customer_id, first_name, last_name,
                               email, hashed_password
                        FROM customers
                        WHERE email = %s
                        """,
                        (email,)
                    )

                    customer = cur.fetchone()

        except psycopg.Error:
            app.logger.exception("Database error while logging in")
            flash("Error logging in. Try again later.", "error")
            return redirect(url_for("login"))

        if customer and bcrypt.checkpw(
            password.encode("utf-8"),
            customer["hashed_password"].encode("utf-8")
        ):
            session.clear()
            session["customer_id"] = customer["customer_id"]
            session["first_name"] = customer["first_name"]

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "customer_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    customer_id = session["customer_id"]

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        c.first_name,
                        a.account_number,
                        a.balance
                    FROM customers c
                    JOIN accounts a
                        ON a.customer_id = c.customer_id
                    WHERE c.customer_id = %s
                    """,
                    (customer_id,)
                )

                account = cur.fetchone()

                if account is None:
                    flash("Account not found.", "error")
                    return redirect(url_for("login"))

    except psycopg.Error:
        app.logger.exception("Dashboard database error")
        flash("Unable to load your dashboard.", "error")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        first_name=account["first_name"],
        account_number=account["account_number"],
        balance=account["balance"]
    )
@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    if "customer_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        customer_id = session["customer_id"]
        amount = parse_amount(request.form.get("amount", ""))
        pin = request.form.get("pin", "").strip()

        if amount is None:
            flash("Enter a valid deposit amount.", "error")
            return redirect(url_for("deposit"))

        if amount < Decimal("1000"):
            flash("The minimum deposit is ₦1,000.", "error")
            return redirect(url_for("deposit"))

        if not re.fullmatch(r"\d{4}", pin):
            flash("Enter your valid 4-digit PIN.", "error")
            return redirect(url_for("deposit"))

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:

                    cur.execute(
                        """
                        SELECT account_id, pin_hash
                        FROM accounts
                        WHERE customer_id = %s
                        FOR UPDATE
                        """,
                        (customer_id,)
                    )

                    account = cur.fetchone()

                    if account is None:
                        flash("Account not found.", "error")
                        return redirect(url_for("dashboard"))

                    if not bcrypt.checkpw(
                        pin.encode("utf-8"),
                        account["pin_hash"].encode("utf-8")
                    ):
                        flash("Incorrect PIN.", "error")
                        return redirect(url_for("deposit"))

                    cur.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1
                            FROM transactions
                            WHERE account_id = %s
                            AND transaction_type = 'DEPOSIT'
                            AND created_at >=
                                CURRENT_TIMESTAMP - INTERVAL '1 hour'
                        ) AS recent_deposit
                        """,
                        (account["account_id"],)
                    )

                    deposit_check = cur.fetchone()

                    if deposit_check["recent_deposit"]:
                        flash(
                            "You can only make one deposit every 60 minutes. Please try again later.",
                            "error"
                        )
                        return redirect(url_for("deposit"))

                    cur.execute(
                        """
                        UPDATE accounts
                        SET balance = balance + %s
                        WHERE account_id = %s
                        """,
                        (amount, account["account_id"])
                    )

                    cur.execute(
                        """
                        INSERT INTO transactions
                        (account_id, transaction_type, amount)
                        VALUES (%s, %s, %s)
                        """,
                        (account["account_id"], "DEPOSIT", amount)
                    )

        except psycopg.Error:
            app.logger.exception("Deposit database error")
            flash("Deposit failed. Please try again.", "error")
            return redirect(url_for("deposit"))

        flash(
            f"₦{amount:,.2f} deposited successfully!",
            "success"
        )
        return redirect(url_for("dashboard"))

    return render_template("deposit.html")

@app.route("/withdraw", methods=["GET", "POST"])
def withdrawal():
    if "customer_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        customer_id = session["customer_id"]
        amount = parse_amount(request.form.get("amount", ""))
        pin = request.form.get("pin", "").strip()

        if amount is None:
            flash("Enter a valid withdrawal amount.", "error")
            return redirect(url_for("withdrawal"))

        if amount < Decimal("200"):
            flash("The minimum withdrawal is ₦200.", "error")
            return redirect(url_for("withdrawal"))

        if amount > Decimal("1000"):
            flash("The maximum withdrawal is ₦1,000 per transaction.", "error")
            return redirect(url_for("withdrawal"))

        if not re.fullmatch(r"\d{4}", pin):
            flash("Enter your valid 4-digit PIN.", "error")
            return redirect(url_for("withdrawal"))

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT account_id, balance, pin_hash
                        FROM accounts
                        WHERE customer_id = %s
                        FOR UPDATE
                        """,
                        (customer_id,)
                    )

                    account = cur.fetchone()

                    if account is None:
                        flash("Account not found.", "error")
                        return redirect(url_for("dashboard"))

                    if not bcrypt.checkpw(
                        pin.encode("utf-8"),
                        account["pin_hash"].encode("utf-8")
                    ):
                        flash("Incorrect PIN.", "error")
                        return redirect(url_for("withdrawal"))

                    if amount > account["balance"]:
                        flash("Insufficient account balance.", "error")
                        return redirect(url_for("withdrawal"))

                    cur.execute(
                        """
                        UPDATE accounts
                        SET balance = balance - %s
                        WHERE account_id = %s
                        """,
                        (amount, account["account_id"])
                    )

                    cur.execute(
                        """
                        INSERT INTO transactions
                        (account_id, transaction_type, amount)
                        VALUES (%s, %s, %s)
                        """,
                        (account["account_id"], "WITHDRAWAL", amount)
                    )

        except psycopg.Error:
            app.logger.exception("Withdrawal database error")
            flash("Withdrawal failed. Please try again.", "error")
            return redirect(url_for("withdrawal"))

        flash(f"₦{amount:,.2f} withdrawn successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("withdrawal.html")

@app.route("/transactions")
def transactions():
    if "customer_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    customer_id = session["customer_id"]

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        t.id,
                        t.transaction_type,
                        t.amount,
                        t.created_at,
                        CASE
                            WHEN t.recipient_account_id = own_account.account_id
                                THEN 'TRANSFER IN'
                            WHEN t.transaction_type = 'TRANSFER'
                                THEN 'TRANSFER OUT'
                            WHEN t.transaction_type = 'ACCOUNT_BONUS'
                                THEN 'ACCOUNT BONUS'
                            ELSE t.transaction_type
                        END AS display_type,
                        CASE
                            WHEN t.recipient_account_id = own_account.account_id
                                THEN sender_account.account_number
                            WHEN t.transaction_type = 'TRANSFER'
                                THEN recipient_account.account_number
                            ELSE NULL
                        END AS related_account
                    FROM transactions t
                    JOIN accounts own_account
                        ON own_account.customer_id = %s
                    LEFT JOIN accounts sender_account
                        ON sender_account.account_id = t.account_id
                    LEFT JOIN accounts recipient_account
                        ON recipient_account.account_id = t.recipient_account_id
                    WHERE
                        t.account_id = own_account.account_id
                        OR t.recipient_account_id = own_account.account_id
                    ORDER BY t.created_at DESC, t.id DESC
                    """,
                    (customer_id,)
                )

                transaction_records = cur.fetchall()

    except psycopg.Error:
        app.logger.exception("Transaction history database error")
        flash("Unable to load transaction history.", "error")
        return redirect(url_for("dashboard"))

    return render_template(
        "transactions.html",
        transactions=transaction_records
    )
    
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "customer_id" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        customer_id = session["customer_id"]
        amount = parse_amount(request.form.get("amount", ""))
        recipient_number = request.form.get("account_number", "").strip()
        pin = request.form.get("pin", "").strip()

        if amount is None:
            flash("Enter a valid transfer amount.", "error")
            return redirect(url_for("transfer"))

        if amount < Decimal("200"):
            flash("The minimum transfer is ₦200.", "error")
            return redirect(url_for("transfer"))

        if amount > Decimal("1000"):
            flash("The maximum transfer is ₦1,000 per transaction.", "error")
            return redirect(url_for("transfer"))

        if not re.fullmatch(r"\d{10}", recipient_number):
            flash("Enter a valid 10-digit recipient account number.", "error")
            return redirect(url_for("transfer"))

        if not re.fullmatch(r"\d{4}", pin):
            flash("Enter your valid 4-digit PIN.", "error")
            return redirect(url_for("transfer"))

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            sender.account_id AS sender_id,
                            recipient.account_id AS recipient_id
                        FROM accounts AS sender
                        CROSS JOIN accounts AS recipient
                        WHERE sender.customer_id = %s
                        AND recipient.account_number = %s
                        """,
                        (customer_id, recipient_number)
                    )

                    account_ids = cur.fetchone()

                    if account_ids is None:
                        flash("Recipient account not found.", "error")
                        return redirect(url_for("transfer"))

                    sender_id = account_ids["sender_id"]
                    recipient_id = account_ids["recipient_id"]

                    if sender_id == recipient_id:
                        flash("You cannot transfer money to your own account.", "error")
                        return redirect(url_for("transfer"))

                    cur.execute(
                        """
                        SELECT account_id, balance, pin_hash
                        FROM accounts
                        WHERE account_id IN (%s, %s)
                        ORDER BY account_id
                        FOR UPDATE
                        """,
                        (sender_id, recipient_id)
                    )

                    locked_accounts = cur.fetchall()

                    accounts = {
                        account["account_id"]: account
                        for account in locked_accounts
                    }

                    sender = accounts.get(sender_id)
                    recipient = accounts.get(recipient_id)

                    if sender is None or recipient is None:
                        flash("Unable to complete transfer. Please try again.", "error")
                        return redirect(url_for("transfer"))

                    if not bcrypt.checkpw(
                        pin.encode("utf-8"),
                        sender["pin_hash"].encode("utf-8")
                    ):
                        flash("Incorrect PIN.", "error")
                        return redirect(url_for("transfer"))

                    if amount > sender["balance"]:
                        flash("Insufficient account balance.", "error")
                        return redirect(url_for("transfer"))

                    cur.execute(
                        """
                        UPDATE accounts
                        SET balance = balance - %s
                        WHERE account_id = %s
                        """,
                        (amount, sender_id)
                    )

                    cur.execute(
                        """
                        UPDATE accounts
                        SET balance = balance + %s
                        WHERE account_id = %s
                        """,
                        (amount, recipient_id)
                    )

                    cur.execute(
                        """
                        INSERT INTO transactions
                        (account_id, transaction_type, amount, recipient_account_id)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (sender_id, "TRANSFER", amount, recipient_id)
                    )

        except psycopg.Error:
            app.logger.exception("Transfer database error")
            flash("Transfer failed. Please try again.", "error")
            return redirect(url_for("transfer"))

        flash(f"₦{amount:,.2f} transferred successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("transfer.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
