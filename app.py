import io
import os
from datetime import datetime
from urllib.parse import urlparse
from uuid import uuid4

import stripe
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from obfuscator import ObfuscationError, obfuscate_python_source

load_dotenv()


def _normalize_database_url(raw_url: str) -> str:
    if raw_url.startswith("postgres://"):
        return raw_url.replace("postgres://", "postgresql://", 1)
    return raw_url


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_database_url(
    os.getenv("DATABASE_URL", "sqlite:///pythonobfus.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_SOURCE_SIZE_BYTES"] = int(os.getenv("MAX_SOURCE_SIZE_BYTES", "200000"))
app.config["ENABLE_DEV_TOPUP"] = os.getenv("ENABLE_DEV_TOPUP", "0") == "1"
app.config["BASE_URL"] = os.getenv("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
app.config["AUTO_APPROVE_PURCHASES"] = os.getenv("AUTO_APPROVE_PURCHASES", "1") == "1"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

CREDIT_PACKAGES = {
    "starter": {
        "label": "Starter",
        "credits": 10,
        "price_cents": 500,
        "price_id": os.getenv("STRIPE_PRICE_ID_STARTER", ""),
    },
    "pro": {
        "label": "Pro",
        "credits": 50,
        "price_cents": 2000,
        "price_id": os.getenv("STRIPE_PRICE_ID_PRO", ""),
    },
    "max": {
        "label": "Max",
        "credits": 150,
        "price_cents": 5000,
        "price_id": os.getenv("STRIPE_PRICE_ID_MAX", ""),
    },
}


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    credits = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    transactions = db.relationship(
        "CreditTransaction",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan",
    )
    obfuscation_jobs = db.relationship(
        "ObfuscationJob",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan",
    )


class CreditTransaction(db.Model):
    __tablename__ = "credit_transactions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    delta = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(64), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=True)
    stripe_session_id = db.Column(db.String(255), nullable=True, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


class ObfuscationJob(db.Model):
    __tablename__ = "obfuscation_jobs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    input_bytes = db.Column(db.Integer, nullable=False)
    output_bytes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def is_safe_redirect(target: str) -> bool:
    if not target:
        return False
    ref = urlparse(request.host_url)
    test = urlparse(target)
    return (not test.netloc) or (test.scheme in ("http", "https") and test.netloc == ref.netloc)


def get_locked_user(user_id: int) -> User | None:
    query = User.query.filter_by(id=user_id)
    if db.engine.url.get_backend_name() != "sqlite":
        query = query.with_for_update()
    return query.first()


def get_package(package_key: str):
    return CREDIT_PACKAGES.get(package_key)


def money(cents: int) -> str:
    return f"${cents / 100:.2f}"


def package_checkout_enabled(package: dict) -> bool:
    return bool(stripe.api_key and package.get("price_id"))


def grant_purchase_credits(
    *,
    user_id: int,
    credits: int,
    stripe_session_id: str,
    amount_cents: int | None,
) -> bool:
    if credits <= 0:
        return False

    try:
        existing = CreditTransaction.query.filter_by(
            stripe_session_id=stripe_session_id
        ).first()
        if existing:
            return False

        user = get_locked_user(user_id)
        if user is None:
            return False

        user.credits += credits
        db.session.add(
            CreditTransaction(
                user_id=user_id,
                delta=credits,
                reason="purchase",
                amount_cents=amount_cents,
                stripe_session_id=stripe_session_id,
            )
        )
        db.session.commit()
        return True
    except IntegrityError:
        db.session.rollback()
        return False
    except Exception:
        db.session.rollback()
        raise


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        user = User(email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("This email is already registered.", "error")
            return render_template("register.html")

        login_user(user)
        flash("Account created.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = User.query.filter_by(email=email).first()
        if user is None or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        login_user(user, remember=remember)
        next_url = request.args.get("next")
        if next_url and is_safe_redirect(next_url):
            return redirect(next_url)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    transactions = (
        CreditTransaction.query.filter_by(user_id=current_user.id)
        .order_by(CreditTransaction.created_at.desc())
        .limit(10)
        .all()
    )
    jobs = (
        ObfuscationJob.query.filter_by(user_id=current_user.id)
        .order_by(ObfuscationJob.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template("dashboard.html", transactions=transactions, jobs=jobs)


@app.route("/obfuscate", methods=["POST"])
@login_required
def obfuscate():
    source = request.form.get("source_code", "")
    filename = request.form.get("filename", "").strip() or "script.py"
    file_part = request.files.get("script_file")

    if file_part and file_part.filename:
        filename = secure_filename(file_part.filename) or filename
        raw = file_part.read()
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError:
            flash("File must be UTF-8 text.", "error")
            return redirect(url_for("dashboard"))

    source = source.strip()
    if not source:
        flash("Provide a Python script first.", "error")
        return redirect(url_for("dashboard"))

    source_size = len(source.encode("utf-8"))
    if source_size > app.config["MAX_SOURCE_SIZE_BYTES"]:
        max_kb = app.config["MAX_SOURCE_SIZE_BYTES"] // 1024
        flash(f"Script too large. Max size is {max_kb} KB.", "error")
        return redirect(url_for("dashboard"))

    try:
        obfuscated = obfuscate_python_source(source)
    except ObfuscationError as exc:
        flash(f"Obfuscation failed: {exc}", "error")
        return redirect(url_for("dashboard"))

    try:
        user = get_locked_user(current_user.id)
        if user is None:
            raise ValueError("User not found.")
        if user.credits < 1:
            raise ValueError("Insufficient credits.")

        user.credits -= 1
        db.session.add(
            CreditTransaction(
                user_id=user.id,
                delta=-1,
                reason="obfuscate",
                amount_cents=None,
                stripe_session_id=None,
            )
        )
        db.session.add(
            ObfuscationJob(
                user_id=user.id,
                filename=filename,
                input_bytes=source_size,
                output_bytes=len(obfuscated.encode("utf-8")),
            )
        )
        db.session.commit()
    except ValueError:
        db.session.rollback()
        flash("You need at least 1 credit to obfuscate.", "error")
        return redirect(url_for("dashboard"))
    except Exception:
        db.session.rollback()
        app.logger.exception("Unexpected obfuscation transaction failure.")
        flash("Obfuscation could not be completed right now.", "error")
        return redirect(url_for("dashboard"))

    output_name = secure_filename(filename) or "script.py"
    if not output_name.endswith(".py"):
        output_name = f"{output_name}.py"
    output_name = f"{output_name[:-3]}_obf.py"

    return send_file(
        io.BytesIO(obfuscated.encode("utf-8")),
        mimetype="text/x-python",
        as_attachment=True,
        download_name=output_name,
    )


@app.route("/buy")
@login_required
def buy_credits():
    packages = []
    for key, pack in CREDIT_PACKAGES.items():
        packages.append(
            {
                "key": key,
                "label": pack["label"],
                "credits": pack["credits"],
                "price": money(pack["price_cents"]),
                "uses_stripe": package_checkout_enabled(pack),
            }
        )
    return render_template(
        "buy.html",
        packages=packages,
        dev_topup_enabled=app.config["ENABLE_DEV_TOPUP"],
        auto_approve_purchases=app.config["AUTO_APPROVE_PURCHASES"],
    )


@app.route("/checkout/<package_key>", methods=["POST"])
@login_required
def create_checkout(package_key: str):
    package = get_package(package_key)
    if package is None:
        abort(404)
    if not package_checkout_enabled(package):
        if not app.config["AUTO_APPROVE_PURCHASES"]:
            flash("Stripe is not configured yet.", "error")
            return redirect(url_for("buy_credits"))

        credited = grant_purchase_credits(
            user_id=current_user.id,
            credits=package["credits"],
            stripe_session_id=f"auto_{uuid4().hex}",
            amount_cents=package["price_cents"],
        )
        if credited:
            flash(
                f"Added {package['credits']} credits instantly (Stripe disabled mode).",
                "success",
            )
            return redirect(url_for("dashboard"))
        flash("Could not add credits right now. Try again.", "error")
        return redirect(url_for("buy_credits"))

    try:
        checkout = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=[{"price": package["price_id"], "quantity": 1}],
            metadata={
                "user_id": str(current_user.id),
                "credits": str(package["credits"]),
                "package_key": package_key,
            },
            client_reference_id=str(current_user.id),
            success_url=(
                f"{app.config['BASE_URL']}"
                f"{url_for('billing_success')}?session_id={{CHECKOUT_SESSION_ID}}"
            ),
            cancel_url=f"{app.config['BASE_URL']}{url_for('buy_credits')}",
        )
    except Exception:
        app.logger.exception("Unable to create Stripe checkout session.")
        flash("Checkout could not start. Try again in a minute.", "error")
        return redirect(url_for("buy_credits"))

    return redirect(checkout.url, code=303)


@app.route("/billing/success")
@login_required
def billing_success():
    session_id = request.args.get("session_id")
    just_credited = False

    if stripe.api_key and session_id:
        try:
            checkout = stripe.checkout.Session.retrieve(session_id)
            metadata = checkout.metadata or {}
            payment_ok = checkout.payment_status == "paid"
            metadata_user_id = int(
                metadata.get("user_id")
                or checkout.client_reference_id
                or 0
            )
            metadata_credits = int(metadata.get("credits") or 0)
            if payment_ok and metadata_user_id == current_user.id and metadata_credits > 0:
                just_credited = grant_purchase_credits(
                    user_id=current_user.id,
                    credits=metadata_credits,
                    stripe_session_id=checkout.id,
                    amount_cents=checkout.amount_total,
                )
        except Exception:
            app.logger.exception("Unable to finalize successful checkout.")

    return render_template("billing_success.html", just_credited=just_credited)


@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    if not stripe.api_key or not STRIPE_WEBHOOK_SECRET:
        return "Webhook not configured.", 400

    payload = request.data
    signature = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, signature, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata") or {}
        try:
            user_id = int(metadata.get("user_id") or session.get("client_reference_id") or 0)
            credits = int(metadata.get("credits") or 0)
        except ValueError:
            user_id = 0
            credits = 0

        if user_id > 0 and credits > 0:
            try:
                grant_purchase_credits(
                    user_id=user_id,
                    credits=credits,
                    stripe_session_id=session["id"],
                    amount_cents=session.get("amount_total"),
                )
            except Exception:
                app.logger.exception("Webhook crediting failed.")
                return "Server error", 500

    return "ok", 200


@app.route("/dev/topup/<package_key>", methods=["POST"])
@login_required
def dev_topup(package_key: str):
    if not app.config["ENABLE_DEV_TOPUP"]:
        abort(404)

    package = get_package(package_key)
    if package is None:
        abort(404)

    try:
        user = get_locked_user(current_user.id)
        if user is None:
            abort(404)
        user.credits += package["credits"]
        db.session.add(
            CreditTransaction(
                user_id=user.id,
                delta=package["credits"],
                reason="dev_topup",
                amount_cents=0,
                stripe_session_id=None,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    flash(f"Added {package['credits']} test credits.", "success")
    return redirect(url_for("buy_credits"))


@app.template_filter("dt")
def format_datetime(value):
    if not value:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
