import pytz # type: ignore
import datetime
from cert_monitor import get_certificate_expiry, get_whois_expiry, db, Domain, Subdomain, app
import os
import subprocess
import time
import logging
from logging.handlers import RotatingFileHandler
from logging.handlers import BaseRotatingHandler


LAST_EMAIL_SENT_FILE = "/cert-monitor/last_email_sent"
LOOP_PAUSE = int(os.getenv('LOOP_PAUSE', 1)) # Minutes
MAX_DATA_AGE = int(os.getenv('MAX_DATA_AGE', 60)) # Minutes
EMAIL_ADD = str(os.getenv('EMAIL_ADD'))

# Get the logging level from the environment variable (default to INFO if not set)
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
# Validate and set the log level
numeric_log_level = getattr(logging, log_level, logging.INFO)

# Configure logging with a rotating file handler
log_file_path = '/cert-monitor/update_data.log'
# Create a RotatingFileHandler
handler = RotatingFileHandler(
    log_file_path,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5  # Keep 5 backup files
)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handler to the root logger
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(numeric_log_level)

class LineCountRotatingFileHandler(BaseRotatingHandler):
    def __init__(self, filename, max_lines=20000, backup_count=5, encoding=None, delay=False):
        self.max_lines = max_lines
        self.backup_count = backup_count
        self.current_line_count = 0
        super().__init__(filename, 'a', encoding, delay)

    def shouldRollover(self, record):
        self.current_line_count += 1
        if self.current_line_count > self.max_lines:
            self.current_line_count = 0  # Reset line count
            return True
        return False

    def doRollover(self):
        if self.stream:
            self.stream.close()
        self.rotate(self.baseFilename, f"{self.baseFilename}.1")
        for i in range(self.backup_count - 1, 0, -1):
            sfn = f"{self.baseFilename}.{i}"
            dfn = f"{self.baseFilename}.{i+1}"
            if os.path.exists(sfn):
                os.rename(sfn, dfn)
        if os.path.exists(self.baseFilename):
            os.rename(self.baseFilename, f"{self.baseFilename}.1")
        self.stream = self._open()

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
            .color-key-table {
                margin-top: 20px;
                width: 100%;
            }
            .color-key-table td {
                text-align: center;
                padding: 3px;
                margin: 0; /* Remove any margins around the text */
                font-weight: bold;
                width: 33%;
                height: 30px; /* Set a specific height */
                line-height: 30px; /* Ensure text aligns vertically within the cell */
                background-color: inherit; /* Make sure the background is inherited or set directly */
            }
            .color-key-table .red {
                background-color: red;
            }
            .color-key-table .orange {
                background-color: orange;
            }
            .color-key-table .yellow {
                background-color: yellow;
            }
            .centered-link {
                text-align: center;
                margin: 20px 0;
            }
            .centered-link a {
                text-decoration: none;
                font-size: 1.2em;
                color: #0066cc;
            }
        </style>
    </head>
    <body>
        <div class="centered-link">
            <a href="https://expiry.vnocsymphony.com" target="_blank">https://expiry.vnocsymphony.com</a>
        </div>
    """


    # Add domain expiries
    html_content += "<h3>Expiring Domains:</h3>"
    if expiring_domains:
        html_content += "<table><tr><th style='width: 50%;'>Domain</th><th style='width: 50%;'>WHOIS Expiry - (YYYY-MM-DD-UTC)</th></tr>"
        for domain in expiring_domains:
            # Ensure `whois_expiry` is timezone-aware
            if domain.whois_expiry and domain.whois_expiry.tzinfo is None:
                domain.whois_expiry = domain.whois_expiry.replace(tzinfo=pytz.UTC)

            days_to_expiry = (domain.whois_expiry - datetime.datetime.now(pytz.UTC)).days  # Use aware datetime
            row_class = "yellow" if days_to_expiry > 7 else ("orange" if days_to_expiry > 0 else "red")
            html_content += f"<tr class='{row_class}'><td>{domain.domain_name}</td><td>{domain.whois_expiry}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>N/A</p>"

    # Add SSL expiries
    html_content += "<br><br><h3>Expiring SSL Certs:</h3>"
    if expiring_ssl:
        html_content += "<table><tr><th style='width: 50%;'>Site</th><th style='width: 50%;'>SSL Expiry - (YYYY-MM-DD-UTC)</th></tr>"
        for subdomain in expiring_ssl:
            # Ensure `expiry_date` is timezone-aware
            if subdomain.expiry_date and subdomain.expiry_date.tzinfo is None:
                subdomain.expiry_date = subdomain.expiry_date.replace(tzinfo=pytz.UTC)

            days_to_expiry = (subdomain.expiry_date - datetime.datetime.now(pytz.UTC)).days  # Use aware datetime
            row_class = "yellow" if days_to_expiry > 7 else ("orange" if days_to_expiry > 0 else "red")
            html_content += f"<tr class='{row_class}'><td>{subdomain.subdomain_name}</td><td>{subdomain.expiry_date}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>N/A</p>"

    # Add color key at the bottom
    html_content += """
    <br><br>
    <h3>Color Key:</h3>
    <table class="color-key-table">
        <tr>
            <td class="red">Expired Already</td>
            <td class="orange">Expires 0-7 days</td>
            <td class="yellow">Expires in 7-30 days</td>
        </tr>
    </table>
    </body></html>
    """

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

        expiring_domains = []
        expiring_ssl = []

        # Fetch all domains from the database
        all_domains = Domain.query.all()
        logging.info(f"Fetched {len(all_domains)} domains from the database.")

        for domain in all_domains:
            # Refresh WHOIS expiry for the domain
            logging.info(f"Refreshing WHOIS expiry for domain {domain.domain_name}")
            whois_expiry, _ = get_whois_expiry(domain.domain_name)  # Call the existing function

            if whois_expiry:
                domain.whois_expiry = whois_expiry  # Update with the new expiry
                domain.last_update = now_utc  # Update the last_update timestamp
                db.session.commit()
                logging.info(f"Updated WHOIS expiry for {domain.domain_name}: {whois_expiry}")
            else:
                logging.warning(f"Failed to refresh WHOIS expiry for {domain.domain_name}")

            # Check if the domain's WHOIS expiry is within 30 days
            if domain.whois_expiry:
                # Ensure `whois_expiry` is timezone-aware
                if domain.whois_expiry.tzinfo is None:
                    domain.whois_expiry = domain.whois_expiry.replace(tzinfo=pytz.UTC)

                # Check if the WHOIS expiry is within 30 days
                if (domain.whois_expiry - now_utc).days <= 30:
                    expiring_domains.append(domain)

            # Refresh SSL expiry for all subdomains of the domain
            subdomains = Subdomain.query.filter_by(domain_id=domain.id).all()
            logging.info(f"Refreshing {len(subdomains)} subdomains for domain {domain.domain_name}")

            for subdomain in subdomains:
                logging.info(f"Refreshing SSL expiry for subdomain {subdomain.subdomain_name}")
                expiry_date, verification_status = get_certificate_expiry(subdomain.subdomain_name)  # Call the existing function

                if expiry_date:
                    subdomain.expiry_date = expiry_date  # Update with the new expiry
                    subdomain.verification_status = verification_status  # Update the verification status
                    subdomain.last_update = now_utc  # Update the last_update timestamp
                    db.session.commit()
                    logging.info(f"Updated SSL expiry for {subdomain.subdomain_name}: {expiry_date}")
                else:
                    logging.warning(f"Failed to refresh SSL expiry for {subdomain.subdomain_name}")
                    subdomain.verification_status = 'grey'  # Mark unreachable
                    subdomain.last_update = now_utc  # Update the last_update timestamp
                    db.session.commit()

                # Check if the subdomain's SSL expiry is within 30 days
                if subdomain.expiry_date:
                    # Ensure `expiry_date` is timezone-aware
                    if subdomain.expiry_date.tzinfo is None:
                        subdomain.expiry_date = subdomain.expiry_date.replace(tzinfo=pytz.UTC)

                    # Check if the SSL expiry is within 30 days
                    if (subdomain.expiry_date - now_utc).days <= 30:
                        expiring_ssl.append(subdomain)

        # Send an alert if there are any expiring domains or SSL certificates
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
