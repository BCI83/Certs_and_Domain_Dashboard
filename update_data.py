import pytz # type: ignore
import datetime
from cert_monitor import get_certificate_expiry, get_whois_expiry, db, Domain, Subdomain, app
import os
import subprocess
import time
import logging

LAST_EMAIL_SENT_FILE = "/cert-monitor/last_email_sent"
LOOP_PAUSE = int(os.getenv('LOOP_PAUSE', 1)) # Minutes
MAX_DATA_AGE = int(os.getenv('MAX_DATA_AGE', 60)) # Minutes
EMAIL_ADD = str(os.getenv('EMAIL_ADD'))

# Get the logging level from the environment variable (default to INFO if not set)
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()

# Configure the logging level based on the environment variable
logging.basicConfig(level=getattr(logging, log_level, logging.INFO))

def has_email_been_sent_today():
    if os.path.exists(LAST_EMAIL_SENT_FILE):
        try:
            with open(LAST_EMAIL_SENT_FILE, 'r') as f:
                last_sent_str = f.read().strip()
                if last_sent_str:
                    last_sent_date = datetime.datetime.strptime(last_sent_str, "%Y-%m-%d").date()
                    logging.info(f"Last email sent date: {last_sent_date}")
                    return last_sent_date == datetime.datetime.utcnow().date()
                else:
                    logging.info("Email has not been sent today (empty date).")
                    return False
        except ValueError:
            logging.info("Invalid date format in last_email_sent.txt, assuming email has not been sent today.")
            return False
    logging.info("No email has been sent today.")
    return False

def mark_email_as_sent_today():
    with open(LAST_EMAIL_SENT_FILE, 'w') as f:
        f.write(datetime.datetime.utcnow().strftime("%Y-%m-%d"))

def build_email_subject(expiring_domains, expiring_ssl):
    urgency_level = "INFO"
    if expiring_domains or expiring_ssl:
        if any((domain.whois_expiry - datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)).days < 7 for domain in expiring_domains):
            urgency_level = "WARNING"
        if any((domain.whois_expiry - datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)).days <= 0 for domain in expiring_domains):
            urgency_level = "CRITICAL"
        if any((sub.expiry_date - datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)).days < 7 for sub in expiring_ssl):
            urgency_level = "WARNING"
        if any((sub.expiry_date - datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)).days <= 0 for sub in expiring_ssl):
            urgency_level = "CRITICAL"

    subject = f"[{urgency_level}] "
    if expiring_domains and expiring_ssl:
        domain_text = f"{len(expiring_domains)} Expiring Domain" if len(expiring_domains) == 1 else f"{len(expiring_domains)} Expiring Domains"
        ssl_text = f"{len(expiring_ssl)} Expiring SSL Certificate" if len(expiring_ssl) == 1 else f"{len(expiring_ssl)} Expiring SSL Certificates"
        subject += f"{domain_text} and {ssl_text}"
    elif expiring_domains:
        subject += f"{len(expiring_domains)} Expiring Domain" if len(expiring_domains) == 1 else f"{len(expiring_domains)} Expiring Domains"
    elif expiring_ssl:
        subject += f"{len(expiring_ssl)} Expiring SSL Certificate" if len(expiring_ssl) == 1 else f"{len(expiring_ssl)} Expiring SSL Certificates"

    return subject

def build_html_email(expiring_domains, expiring_ssl):
    html_content = """
    <html>
    <head>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
                width: 50%; /* Ensure both tables have the same column width */
            }
            th {
                background-color: #f2f2f2;
            }
            .yellow { background-color: yellow; }
            .orange { background-color: orange; }
            .red { background-color: red; }
        </style>
    </head>
    <body>
    """

    # Add domain expiries
    html_content += "<h3>Expiring Domains:</h3>"
    if expiring_domains:
        html_content += "<table><tr><th style='width: 50%;'>Domain</th><th style='width: 50%;'>WHOIS Expiry  (YYYY-MM-DD-UTC)</th></tr>"
        for domain in expiring_domains:
            days_to_expiry = (domain.whois_expiry - datetime.datetime.now(pytz.UTC)).days  # Use aware datetime
            row_class = "yellow" if days_to_expiry > 7 else ("orange" if days_to_expiry > 0 else "red")
            html_content += f"<tr class='{row_class}'><td>{domain.domain_name}</td><td>{domain.whois_expiry}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>N/A</p>"

    # Add SSL expiries
    html_content += "<br><br><h3>Expiring SSL Certs:</h3>"
    if expiring_ssl:
        html_content += "<table><tr><th style='width: 50%;'>Site</th><th style='width: 50%;'>SSL Expiry  (YYYY-MM-DD-UTC)</th></tr>"
        for subdomain in expiring_ssl:
            days_to_expiry = (subdomain.expiry_date - datetime.datetime.now(pytz.UTC)).days  # Use aware datetime
            row_class = "yellow" if days_to_expiry > 7 else ("orange" if days_to_expiry > 0 else "red")
            html_content += f"<tr class='{row_class}'><td>{subdomain.subdomain_name}</td><td>{subdomain.expiry_date}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>N/A</p>"

    html_content += "</body></html>"
    return html_content


def send_email(to_address, subject, body_content, from_address="Symphony Certificate and Domain Monitor <admin@certificate.monitor>"):
    command = f'echo "{body_content}" | mail -s "{subject}" -a "From: {from_address}" -a "Content-Type: text/html" {to_address}'
    logging.info(f"Executing email command: {command}")
    try:
        subprocess.run(command, shell=True, check=True)
        logging.info(f"Email successfully sent to {to_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to send email: {e}")

def update_expiry_data():
    with app.app_context():
        logging.info("Starting expiry data update.")
        now_utc = datetime.datetime.now(pytz.UTC)  # Current UTC time (aware)
        logging.info(f"Current UTC time: {now_utc}")
        update_threshold = now_utc - datetime.timedelta(minutes=MAX_DATA_AGE)
        expiring_domains = []
        expiring_ssl = []

        all_domains = Domain.query.all()
        logging.info(f"Fetched {len(all_domains)} domains from the database.")

        for domain in all_domains:
            # Check WHOIS expiry for domain
            logging.info(f"Checking WHOIS expiry for domain {domain.domain_name}")
            if domain.whois_expiry:
                # Ensure whois_expiry is timezone-aware (in UTC)
                if domain.whois_expiry.tzinfo is None:
                    domain.whois_expiry = domain.whois_expiry.replace(tzinfo=pytz.UTC)

                days_to_expiry = (domain.whois_expiry - now_utc).days
                logging.info(f"Domain {domain.domain_name} expires in {days_to_expiry} days.")
                if days_to_expiry <= 30:
                    expiring_domains.append(domain)

            # Check SSL expiry for subdomains
            subdomains = Subdomain.query.filter_by(domain_id=domain.id).all()
            logging.info(f"Checking {len(subdomains)} subdomains for domain {domain.domain_name}")

            for subdomain in subdomains:
                logging.info(f"Checking SSL expiry for subdomain {subdomain.subdomain_name}")
                if subdomain.expiry_date:
                    # Ensure expiry_date is timezone-aware (in UTC)
                    if subdomain.expiry_date.tzinfo is None:
                        subdomain.expiry_date = subdomain.expiry_date.replace(tzinfo=pytz.UTC)

                    days_to_expiry = (subdomain.expiry_date - now_utc).days
                    logging.info(f"Subdomain {subdomain.subdomain_name} expires in {days_to_expiry} days.")
                    if days_to_expiry <= 30:
                        logging.info(f"Subdomain {subdomain.subdomain_name} added to expiring SSL list.")
                        expiring_ssl.append(subdomain)

        # Now check if there are any expiring items to send an email
        if expiring_domains or expiring_ssl:
            logging.info(f"Found {len(expiring_domains)} expiring domains and {len(expiring_ssl)} expiring SSL certificates.")
            if not has_email_been_sent_today():
                logging.info("Email has not been sent today, preparing to send email.")
                html_email_content = build_html_email(expiring_domains, expiring_ssl)
                email_subject = build_email_subject(expiring_domains, expiring_ssl)
                logging.info(f"Email subject: {email_subject}")
                send_email(EMAIL_ADD, email_subject, html_email_content)
                mark_email_as_sent_today()
            else:
                logging.info("Email has already been sent today, skipping email.")
        else:
            logging.info("No expiring items found.")



def main():
    while True:
        update_expiry_data()

        # Sleep in small increments to handle SIGTERM quickly
        for _ in range(60 * LOOP_PAUSE):
            time.sleep(1)

if __name__ == "__main__":
    logging.info("Starting monitoring script.")
    main()
