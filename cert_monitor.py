from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user # type: ignore
from flask import Flask, render_template, redirect, url_for, request, jsonify, send_file, flash, redirect
from flask_sqlalchemy import SQLAlchemy # type: ignore
import datetime
from datetime import timedelta
import pytz # type: ignore
import ssl
import re
import os
import OpenSSL # type: ignore
import socket
import logging
import subprocess
import io
from werkzeug.utils import secure_filename
import requests

# Get the logging level from the environment variable (default to INFO if not set)
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
# Configure the logging level based on the environment variable
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))

SQLALCHEMY_DATABASE_URI = str(os.getenv('SQLALCHEMY_DATABASE_URI'))

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = str(os.getenv('ADMIN_PASS'))

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id

    # Flask-Login requires is_active, is_authenticated, is_anonymous attributes.
    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

# Configure SQLAlchemy for PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models for Domain and Subdomain
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    whois_expiry = db.Column(db.DateTime, nullable=True)
    last_update = db.Column(db.DateTime, nullable=True)

class Subdomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subdomain_name = db.Column(db.String(255), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=True)
    verification_status = db.Column(db.String(10), nullable=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    domain = db.relationship('Domain', backref=db.backref('subdomains', lazy=True))
    notes = db.Column(db.Text, nullable=True)
    last_update = db.Column(db.DateTime, nullable=True)

# Ensure that the tables are created at startup
def create_tables():
    with app.app_context():
        db.create_all()

# Call the function to create tables
create_tables()

# Route to export the database
@app.route('/export_db', methods=['GET'])
@login_required
def export_db():
    try:
        # Path to export the database
        db_export_path = "/tmp/exported_database.sql"

        # Use `pg_dump` to export the entire database schema and data
        export_command = f"pg_dump --dbname=postgresql://certmonitoruser:Passw0rd@db:5432/certmonitor --no-owner --no-privileges --file={db_export_path}"
        result = os.system(export_command)

        # Check if the export command succeeded
        if result != 0:
            logging.error("Database export failed.")
            return "Failed to export database.", 500

        # Serve the file as a download
        return send_file(db_export_path, as_attachment=True, download_name="expiry_db_export.sql")
    except Exception as e:
        logging.error(f"Error during database export: {e}")
        return "Failed to export database.", 500

# Route to import the database
@app.route('/import_db', methods=['POST'])
@login_required
def import_db():
    temp_file_path = None  # Initialize the variable
    try:
        # Get the uploaded file
        file = request.files.get('file')

        # Ensure a file is selected
        if not file:
            return "No file selected.", 400

        # Validate the file extension
        if not file.filename.lower().endswith('.sql'):
            return "Invalid file format. Please upload a .sql file.", 400

        # Save the uploaded file temporarily
        temp_file_path = f"/tmp/{file.filename}"
        file.save(temp_file_path)

        # Use `psql` to import the database
        import_command = f"psql --username=certmonitoruser --host=db --port=5432 --dbname=certmonitor -f {temp_file_path}"
        result = os.system(import_command)

        # Check if the import command succeeded
        if result != 0:
            logging.error("Database import failed.")
            return "Failed to import database.", 500

        # Return success message
        return "Database imported successfully.", 200

    except Exception as e:
        logging.error(f"Error during database import: {e}")
        return "Failed to import database.", 500

    finally:
        # Ensure the temporary file is deleted
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def validate_sql_file(file_path):
    """
    Validate that the SQL file contains the expected tables and columns.
    """
    required_tables = {
        "domain": ["id", "domain_name", "whois_expiry", "last_update"],
        "subdomain": ["id", "subdomain_name", "expiry_date", "verification_status", "domain_id", "notes", "last_update"],
    }

    try:
        # Read the file and parse the SQL commands
        with open(file_path, "r") as file:
            sql_content = file.read().lower()

        # Check for required tables and columns
        for table, columns in required_tables.items():
            if f"create table {table}" not in sql_content:
                return {"valid": False, "error": f"Missing table: {table}"}

            for column in columns:
                if f"{column}" not in sql_content:
                    return {"valid": False, "error": f"Missing column '{column}' in table '{table}'"}

        return {"valid": True}
    except Exception as e:
        logging.error(f"Error validating SQL file: {e}")
        return {"valid": False, "error": "Unable to validate file"}

def get_certificate_expiry(domain):
    domain = domain.replace("https://", "").replace("http://", "")
    if ':' in domain:
        hostname, port = domain.split(':')
        port = int(port)
    else:
        hostname = domain
        port = 443

    # First attempt: verified connection with a timeout of 5 seconds
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=2) as sock:  # Shortened timeout to 5 seconds
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                expiry_date_str = x509.get_notAfter().decode("ascii")
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=pytz.UTC)  # Ensure expiry is in UTC
                logging.debug(f"Certificate expiry for {domain}: {expiry_date}")
                return expiry_date, 'green'
    except Exception as e:
        logging.debug(f"Verified certificate fetch failed for {domain}: {e}")

    # Second attempt: unverified connection with a timeout of 5 seconds
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=2) as sock:  # Shortened timeout to 5 seconds
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                expiry_date_str = x509.get_notAfter().decode("ascii")
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=pytz.UTC)  # Ensure expiry is in UTC
                logging.debug(f"Unverified certificate expiry for {domain}: {expiry_date}")
                return expiry_date, 'red'
    except Exception as e:
        logging.debug(f"Unverified certificate fetch failed for {domain}: {e}")

    # If both attempts fail, mark the domain as unreachable
    logging.debug(f"Site unreachable for {domain}")
    return None, 'grey'


def get_whois_expiry(domain):
    """
    Get the expiration date of the domain by running the whois command.
    Handles variations in WHOIS output formats, including milliseconds.
    """
    try:
        # Run the whois command
        result = subprocess.run(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        # Adjust the regex to account for both 'Registrar Registration Expiration Date' and 'Registry Expiry Date'
        match = re.search(r'(Registrar Registration Expiration Date|Registry Expiry Date):\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)', output)

        if match:
            expiry_str = match.group(2)

            # Parse the datetime string, considering both Z and +0000 timezones and millisecond precision
            if '.' in expiry_str:
                expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%SZ")

            expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)  # Make it explicitly timezone-aware

            logging.debug(f"WHOIS expiry for {domain}: {expiry_date} (type: {type(expiry_date)})")
            return expiry_date, "green"  # Return the expiry date and a normal status

        else:
            logging.error(f"No WHOIS expiry date found for {domain}")
            return None, "error"  # Return None if no expiry date is found

    except Exception as e:
        logging.error(f"Error fetching WHOIS data for {domain}: {e}")
        return None, "error"  # Return None in case of an error

def load_sites():
    sites = {}
    all_domains = Domain.query.all()

    # Loop through all domains and process WHOIS expiry
    for domain in all_domains:
        # Add the main domain's WHOIS expiry to the sites dictionary
        whois_expiry = domain.whois_expiry
        sites[domain.domain_name] = []

        if whois_expiry:
            # Ensure whois_expiry is timezone-aware
            if whois_expiry.tzinfo is None:
                whois_expiry = whois_expiry.replace(tzinfo=pytz.UTC)

            now_aware = datetime.datetime.now(pytz.UTC)  # Make current time timezone-aware
            color = 'green' if whois_expiry > now_aware else 'red'
            sites[domain.domain_name].append({
                'id': domain.id,
                'domain': domain.domain_name,
                'whois_expiry': whois_expiry,  # Note: We now use 'whois_expiry' for main domains
                'verification_status': color
            })

        # Fetch subdomains linked to this domain
        subdomains = Subdomain.query.filter_by(domain_id=domain.id).all()

        for subdomain in subdomains:
            expiry = subdomain.expiry_date

            # Ensure the certificate expiry is timezone-aware if not already
            if expiry and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=pytz.UTC)

            now_aware = datetime.datetime.now(pytz.UTC)  # Make current time timezone-aware
            if expiry:
                if expiry > now_aware + timedelta(days=30):
                    color = 'green'
                elif expiry > now_aware + timedelta(days=7):
                    color = 'orange'
                else:
                    color = 'red'
            else:
                color = 'red'

            verification_status = subdomain.verification_status or color

            # Add subdomain entry to the corresponding main domain
            sites[domain.domain_name].append({
                'id': subdomain.id,
                'domain': subdomain.subdomain_name,
                'expiry': expiry,
                'verification_status': verification_status  # Pass the verification status
            })

    return sites

#@app.before_request
#def before_request():
#    if not request.is_secure:
#        return redirect(request.url.replace("http://", "https://"))

@app.route('/')
def dashboard():
    sites = load_sites()  # Load sites from the database
    now_aware = datetime.datetime.now(pytz.utc)
    return render_template('dashboard.html', sites=sites, timedelta=timedelta, now=now_aware)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = 'admin'
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Use the AdminUser class instead of a dictionary
            user = AdminUser(id=1)
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@login_manager.user_loader
def load_user(user_id):
    # Return the admin user since there's only one user
    if user_id == "1":
        return AdminUser(id=1)
    return None

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('dashboard'))

@app.route('/check_login')
def check_login():
    logging.info(f'Login check: {current_user.is_authenticated}')  # Log the login check status
    if current_user.is_authenticated:
        return jsonify({'logged_in': True})
    return jsonify({'logged_in': False})

@app.route('/save_notes/<int:subdomain_id>', methods=['POST'])
@login_required
def save_notes(subdomain_id):
    # Fetch the subdomain using the provided ID
    subdomain = Subdomain.query.get_or_404(subdomain_id)

    # Get the notes from the form data
    notes = request.form.get('notes')

    # Update the notes for the subdomain
    subdomain.notes = notes

    # Commit the changes to the database
    db.session.commit()

    # Redirect back to the main dashboard after saving
    return redirect(url_for('dashboard'))


@app.route('/add_site', methods=['POST'])
@login_required
def add_site_route():
    domain = request.form['domain'].strip()

    # Remove trailing slash if present
    domain = domain.rstrip('/')

    # Prepend https:// if the domain doesn't start with http or https
    if not domain.startswith('https://') and not domain.startswith('http://'):
        domain = f'https://{domain}'

    # Remove the protocol before storing the domain
    domain_without_protocol = domain.replace("https://", "").replace("http://", "")

    # Remove port if present for the main domain
    domain_without_port = domain_without_protocol.split(':')[0]

    # Validate that the domain has at least two parts (e.g., example.com)
    domain_parts = domain_without_port.split('.')
    if len(domain_parts) < 2:
        return "Invalid domain", 400

    # Extract the main domain (e.g., "example.com")
    main_domain = domain_parts[-2] + '.' + domain_parts[-1]

    # Check if the domain already exists in the database
    existing_domain = Domain.query.filter_by(domain_name=main_domain).first()
    if existing_domain:
        new_domain = existing_domain
    else:
        # Perform WHOIS lookup for the main domain lease expiry
        whois_expiry, status = get_whois_expiry(main_domain)

        # If WHOIS expiry is None, handle it gracefully
        if whois_expiry is None:
            logging.error(f"WHOIS expiry not found for {main_domain}, not adding domain.")
            return f"Failed to retrieve WHOIS data for {main_domain}", 400

        # Create new main domain entry with WHOIS expiry data and populate the last_update field
        new_domain = Domain(domain_name=main_domain, whois_expiry=whois_expiry, last_update=datetime.datetime.now(pytz.UTC))
        db.session.add(new_domain)
        db.session.commit()

    # Add subdomain to the Subdomain table (if it doesn't exist)
    subdomain = Subdomain.query.filter_by(subdomain_name=domain_without_protocol, domain_id=new_domain.id).first()
    if not subdomain:
        # Perform the certificate expiry check for the subdomain
        expiry_date, verification_status = get_certificate_expiry(domain_without_protocol)

        # If the subdomain is unreachable, handle it gracefully
        if verification_status == 'grey':
            logging.info(f"Subdomain {domain_without_protocol} is unreachable.")

        # Create the subdomain and populate the last_update field
        subdomain = Subdomain(
            subdomain_name=domain_without_protocol,
            domain_id=new_domain.id,
            expiry_date=expiry_date,
            verification_status=verification_status,
            last_update=datetime.datetime.now(pytz.UTC),
            notes=''
        )
        db.session.add(subdomain)
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/subdomain/<int:subdomain_id>', methods=['GET', 'POST'])
@login_required
def subdomain_detail(subdomain_id):
    subdomain = Subdomain.query.get_or_404(subdomain_id)
    return render_template('subdomain_detail.html', subdomain=subdomain)



@app.route('/delete_site/<domain>', methods=['POST'])
@login_required  # This ensures the user is logged in before deleting
def delete_site(domain):
    try:
        # Find the subdomain in the database
        subdomain = Subdomain.query.filter_by(subdomain_name=domain).first()

        if subdomain:
            # Delete the subdomain
            db.session.delete(subdomain)
            db.session.commit()
            logging.info(f"Removed subdomain from DB: {domain}")

            # Check if the domain has any other subdomains
            remaining_subdomains = Subdomain.query.filter_by(domain_id=subdomain.domain_id).count()

            # If no other subdomains remain, delete the main domain
            if remaining_subdomains == 0:
                main_domain = Domain.query.filter_by(id=subdomain.domain_id).first()
                if main_domain:
                    db.session.delete(main_domain)
                    db.session.commit()
                    logging.info(f"Removed domain from DB: {main_domain.domain_name}")

            return redirect(url_for('dashboard'))  # Redirect to dashboard on success
        else:
            logging.error(f"Subdomain not found in DB: {domain}")
            return 'Subdomain not found', 404  # Not found

    except Exception as e:
        logging.error(f"Error deleting site {domain}: {e}")
        return str(e), 500  # Server error

@app.route('/site/<domain>')
@login_required
def site_detail(domain):
    # Fetch and display information about the given domain/subdomain
    site = Domain.query.filter_by(domain_name=domain).first() or Subdomain.query.filter_by(subdomain_name=domain).first()

    if not site:
        return "Domain or subdomain not found", 404

    return render_template('site_detail.html', site=site)

if __name__ == '__main__':
    app.run(debug=True)
