from flask import Flask, render_template, redirect, url_for, request
from datetime import timedelta
import os
import re
import datetime
import ssl
import OpenSSL
import socket
import logging
import subprocess
import pytz

# Set up basic logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

SITES_DIR = "/cert-monitor/sites"  # Define your sites directory

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
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y%m%d%H%M%SZ")
                return expiry_date, 'green'
    except Exception as e:
        logging.warning(f"Verification failed for {domain}: {e}")

    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
                expiry_date_str = x509.get_notAfter().decode("ascii")
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%Y%m%d%H%M%SZ")
                return expiry_date, 'red'
    except Exception as e:
        logging.error(f"Error fetching certificate for {domain}: {e}")
        return None, 'error'

def load_sites():
    sites = {}
    if os.path.exists(SITES_DIR):
        for main_domain in os.listdir(SITES_DIR):
            domain_path = os.path.join(SITES_DIR, main_domain)
            if os.path.isdir(domain_path):
                sites[main_domain] = []

                # Get WHOIS expiration date for the main domain
                whois_expiry = get_whois_expiry(main_domain)
                logging.debug(f"WHOIS expiry for {main_domain}: {whois_expiry} (type: {type(whois_expiry)})")

                if whois_expiry:
                    # Ensure whois_expiry is timezone-aware
                    if whois_expiry.tzinfo is None:
                        whois_expiry = whois_expiry.replace(tzinfo=pytz.UTC)

                    sites[main_domain].append({
                        'domain': main_domain,
                        'expiry': whois_expiry,
                        'verification_status': 'green' if whois_expiry > datetime.datetime.now(pytz.UTC) else 'red'
                    })

                # Process subdomains as usual
                for subdomain_file in os.listdir(domain_path):
                    with open(os.path.join(domain_path, subdomain_file), 'r') as f:
                        subdomain = f.read().strip()
                        expiry, status = get_certificate_expiry(subdomain)

                        # Ensure certificate expiry is timezone-aware
                        if expiry and expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=pytz.UTC)

                        logging.debug(f"Certificate expiry for {subdomain}: {expiry} (type: {type(expiry)})")

                        sites[main_domain].append({
                            'domain': subdomain,
                            'expiry': expiry,
                            'verification_status': status
                        })
    return sites

@app.route('/')
def dashboard():
    sites = load_sites()  # Load sites from the directory structure
    now_aware = datetime.datetime.now(pytz.utc)  # Make now timezone-aware (UTC)
    return render_template('dashboard.html', sites=sites, timedelta=timedelta, now=now_aware)

@app.route('/site/<domain>')
def site_detail(domain):
    # Code to handle the site detail view
    return render_template('site_detail.html', domain=domain)

@app.route('/add_site', methods=['POST'])
def add_site_route():
    domain = request.form['domain'].strip()
    if not domain.startswith('https://') and not domain.startswith('http://'):
        domain = f'https://{domain}'
    domain_without_protocol = domain.replace("https://", "").replace("http://", "")
    domain_parts = domain_without_protocol.split('.')
    if len(domain_parts) < 2:
        return "Invalid domain", 400
    main_domain = domain_parts[-2] + '.' + domain_parts[-1]
    domain_path = os.path.join(SITES_DIR, main_domain)
    if not os.path.exists(domain_path):
        os.makedirs(domain_path)
    subdomain_file = os.path.join(domain_path, domain_without_protocol + ".txt")
    if not os.path.exists(subdomain_file):
        with open(subdomain_file, "w") as f:
            f.write(domain)
    return redirect(url_for('dashboard'))

@app.route('/delete_site/<domain>', methods=['POST'])
def delete_site(domain):
    try:
        main_domain = domain.split('.')[-2] + '.' + domain.split('.')[-1]
        domain_path = os.path.join(SITES_DIR, main_domain)
        subdomain_file = os.path.join(domain_path, domain.replace("https://", "").replace("http://", "") + ".txt")
        if os.path.exists(subdomain_file):
            os.remove(subdomain_file)
            if len(os.listdir(domain_path)) == 0:
                os.rmdir(domain_path)
            return '', 204
        else:
            return 'Subdomain not found', 404
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True)

