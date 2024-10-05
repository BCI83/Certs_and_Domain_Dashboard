from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
import datetime
from datetime import timedelta
import pytz
import ssl
import re
import OpenSSL
import socket
import logging
import subprocess

logging.basicConfig(level=logging.WARNING)

app = Flask(__name__)

# Configure SQLAlchemy for PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://certmonitoruser:your_password_here@db:5432/certmonitor'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models for Domain and Subdomain
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False)
    whois_expiry = db.Column(db.DateTime, nullable=True)
    last_update = db.Column(db.DateTime, nullable=True)  # New field for last update

class Subdomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subdomain_name = db.Column(db.String(255), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=True)
    verification_status = db.Column(db.String(10), nullable=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    domain = db.relationship('Domain', backref=db.backref('subdomains', lazy=True))
    notes = db.Column(db.Text, nullable=True)  # New field for notes
    last_update = db.Column(db.DateTime, nullable=True)  # New field for last update

# Ensure that the tables are created at startup
def create_tables():
    with app.app_context():
        db.create_all()

# Call the function to create tables
create_tables()

def get_certificate_expiry(domain):
    domain = domain.replace("https://", "").replace("http://", "")
    if ':' in domain:
        hostname, port = domain.split(':')
        port = int(port)
    else:
        hostname = domain
        port = 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                expiry_date_str = x509.get_notAfter().decode("ascii")
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=pytz.UTC)  # Ensure expiry is in UTC
                logging.debug(f"Certificate expiry for {domain}: {expiry_date}")
                return expiry_date, 'green'
    except Exception as e:
        logging.debug(f"Verification failed for {domain}: {e}")

    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                expiry_date_str = x509.get_notAfter().decode("ascii")
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=pytz.UTC)  # Ensure expiry is in UTC
                logging.debug(f"Unverified certificate expiry for {domain}: {expiry_date}")
                return expiry_date, 'red'
    except Exception as e:
        logging.error(f"Error fetching certificate for {domain}: {e}")
        return None, 'error'

def get_whois_expiry(domain):
    """
    Get the expiration date of the domain by running the whois command.
    Handles variations in WHOIS output formats, including milliseconds.
    """
    try:
        # Run the whois command
        result = subprocess.run(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        # Adjust the regex to account for variations in date format (Z, +0000, milliseconds)
        match = re.search(r'Registrar Registration Expiration Date:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(Z|\+\d{4}))', output)

        if match:
            expiry_str = match.group(1)

            # Parse the datetime string, considering both Z and +0000 timezones and millisecond precision
            if expiry_str.endswith('Z'):
                # Handle with milliseconds if present
                if '.' in expiry_str:
                    expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                else:
                    expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%SZ")
                expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)  # Make it explicitly timezone-aware
            else:
                # Handle +0000 and similar offsets
                expiry_date = datetime.datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S%z")

            logging.debug(f"WHOIS expiry for {domain}: {expiry_date} (type: {type(expiry_date)})")
            return expiry_date  # Return the timezone-aware datetime object

        else:
            logging.error(f"No WHOIS expiry date found for {domain}")
            return None
    except Exception as e:
        logging.error(f"Error fetching WHOIS data for {domain}: {e}")
        return None

def load_sites():
    sites = {}
    all_domains = Domain.query.all()

    # Loop through all domains and process WHOIS expiry
    for domain in all_domains:
        sites[domain.domain_name] = []
        whois_expiry = domain.whois_expiry

        # WHOIS expiry check
        if whois_expiry:
            # Ensure whois_expiry is timezone-aware
            if whois_expiry.tzinfo is None:
                whois_expiry = whois_expiry.replace(tzinfo=pytz.UTC)

            now_aware = datetime.datetime.now(pytz.UTC)  # Make current time timezone-aware
            color = 'green' if whois_expiry > now_aware else 'red'
            sites[domain.domain_name].append({
                'id': domain.id,  # Ensure domain id is passed
                'domain': domain.domain_name,
                'expiry': whois_expiry,
                'verification_status': color
            })

        # Subdomains and their expiry
        subdomains = Subdomain.query.filter_by(domain_id=domain.id).all()

        for subdomain in subdomains:
            expiry = subdomain.expiry_date

            # Ensure the certificate expiry is timezone-aware if not already
            if expiry and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=pytz.UTC)

            # Define color logic for the certificate expiry
            if expiry:
                if expiry > now_aware + timedelta(days=30):
                    color = 'green'
                elif expiry > now_aware + timedelta(days=7):
                    color = 'orange'
                else:
                    color = 'red'
            else:
                color = 'red'

            # Use verification_status from the database or fallback to calculated color
            verification_status = subdomain.verification_status or color

            sites[domain.domain_name].append({
                'id': subdomain.id,  # Ensure subdomain ID is included
                'domain': subdomain.subdomain_name,
                'expiry': expiry,
                'verification_status': verification_status  # Pass the correct verification status
            })

    return sites

@app.route('/')
def dashboard():
    sites = load_sites()  # Load sites from the database
    now_aware = datetime.datetime.now(pytz.utc)
    return render_template('dashboard.html', sites=sites, timedelta=timedelta, now=now_aware)

@app.route('/save_notes/<int:subdomain_id>', methods=['POST'])
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
        whois_expiry = get_whois_expiry(main_domain)

        # Create new main domain entry with WHOIS expiry data and populate the last_update field
        new_domain = Domain(domain_name=main_domain, whois_expiry=whois_expiry, last_update=datetime.datetime.now(pytz.UTC))
        db.session.add(new_domain)
        db.session.commit()

    # Add subdomain to the Subdomain table (if it doesn't exist)
    subdomain = Subdomain.query.filter_by(subdomain_name=domain_without_protocol, domain_id=new_domain.id).first()
    if not subdomain:
        # Perform the certificate expiry check for the subdomain
        expiry_date, verification_status = get_certificate_expiry(domain_without_protocol)

        # Create the subdomain and populate the last_update field
        subdomain = Subdomain(subdomain_name=domain_without_protocol, domain_id=new_domain.id, expiry_date=expiry_date,
                              verification_status=verification_status, last_update=datetime.datetime.now(pytz.UTC))
        db.session.add(subdomain)
        db.session.commit()

    return redirect(url_for('dashboard'))


@app.route('/subdomain/<int:subdomain_id>', methods=['GET', 'POST'])
def subdomain_detail(subdomain_id):
    subdomain = Subdomain.query.get_or_404(subdomain_id)
    return render_template('subdomain_detail.html', subdomain=subdomain)



@app.route('/delete_site/<domain>', methods=['POST'])
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

            return '', 204  # No content (successful deletion)
        else:
            logging.error(f"Subdomain not found in DB: {domain}")
            return 'Subdomain not found', 404  # Not found

    except Exception as e:
        logging.error(f"Error deleting site {domain}: {e}")
        return str(e), 500  # Server error

@app.route('/site/<domain>')
def site_detail(domain):
    # Fetch and display information about the given domain/subdomain
    site = Domain.query.filter_by(domain_name=domain).first() or Subdomain.query.filter_by(subdomain_name=domain).first()

    if not site:
        return "Domain or subdomain not found", 404

    return render_template('site_detail.html', site=site)

if __name__ == '__main__':
    app.run(debug=True)
