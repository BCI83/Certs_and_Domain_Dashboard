from cert_monitor import get_certificate_expiry, get_whois_expiry, db, Domain, Subdomain, app
import signal
import datetime
import os
import pytz
import time
import logging
import subprocess

LAST_EMAIL_SENT_FILE = "/cert-monitor/last_email_sent"

# Set logging level to WARNING to avoid DEBUG logs
logging.basicConfig(level=logging.WARNING)

# Get update interval from environment variables (default to 60 minutes)
UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL', 60))
shutdown_flag = False

def signal_handler(signum, frame):
    global shutdown_flag
    shutdown_flag = True
    print("Received shutdown signal, exiting...")

# Register signal handler for SIGTERM
signal.signal(signal.SIGTERM, signal_handler)

# This function must run within the app context to interact with the database
def update_expiry_data():
    with app.app_context():  # Ensure Flask app context is available
        now_utc = datetime.datetime.now(pytz.UTC)
        update_threshold = now_utc - datetime.timedelta(minutes=UPDATE_INTERVAL)

        # Fetch all domains
        all_domains = Domain.query.all()

        for domain in all_domains:
            # Ensure last_update is timezone-aware (in UTC) before comparing
            if domain.last_update is not None:
                if domain.last_update.tzinfo is None:
                    domain_last_update = domain.last_update.replace(tzinfo=pytz.UTC)
                else:
                    domain_last_update = domain.last_update
            else:
                domain_last_update = None

            if domain_last_update is None or domain_last_update < update_threshold:
                now_utc = datetime.datetime.now(pytz.UTC)
                whois_expiry = get_whois_expiry(domain.domain_name)
                if whois_expiry:
                    domain.whois_expiry = whois_expiry
                    domain.last_update = now_utc

                subdomains = Subdomain.query.filter_by(domain_id=domain.id).all()

                for subdomain in subdomains:
                    if subdomain.last_update is not None:
                        if subdomain.last_update.tzinfo is None:
                            subdomain_last_update = subdomain.last_update.replace(tzinfo=pytz.UTC)
                        else:
                            subdomain_last_update = subdomain.last_update
                    else:
                        subdomain_last_update = None

                    if subdomain_last_update is None or subdomain_last_update < update_threshold:
                        now_utc = datetime.datetime.now(pytz.UTC)
                        expiry_date, verification_status = get_certificate_expiry(subdomain.subdomain_name)
                        if expiry_date:
                            subdomain.expiry_date = expiry_date
                            subdomain.verification_status = verification_status
                            subdomain.last_update = now_utc

        db.session.commit()

def send_email(to_address, subject, body_file, from_address="Symphony Certificate and Domain Monitor <admin@certificate.monitor>"):
    command = f'mail -s "{subject}" -a "From: {from_address}" {to_address} < {body_file}'
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Email sent to {to_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to send email: {e}")

def has_email_been_sent_today():
    if os.path.exists(LAST_EMAIL_SENT_FILE):
        try:
            with open(LAST_EMAIL_SENT_FILE, 'r') as f:
                last_sent_str = f.read().strip()
                if last_sent_str:
                    last_sent_date = datetime.datetime.strptime(last_sent_str, "%Y-%m-%d").date()
                    return last_sent_date == datetime.datetime.utcnow().date()
                else:
                    print("No valid date in last_email_sent.txt, assuming email has not been sent today.")
                    return False
        except ValueError:
            print("Invalid date format in last_email_sent.txt, assuming email has not been sent today.")
            return False
    return False

def mark_email_as_sent_today():
    with open(LAST_EMAIL_SENT_FILE, 'w') as f:
        f.write(datetime.datetime.utcnow().strftime("%Y-%m-%d"))

# This function must run within the app context to interact with the database
def get_expiring_domains_and_ssl():
    with app.app_context():  # Ensure Flask app context is available
        now_utc = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
        thirty_days_from_now = now_utc + datetime.timedelta(days=30)

        expiring_domains = Domain.query.filter(Domain.whois_expiry.isnot(None), Domain.whois_expiry <= thirty_days_from_now).all()
        expiring_ssl = Subdomain.query.filter(Subdomain.expiry_date.isnot(None), Subdomain.expiry_date <= thirty_days_from_now).all()

        return expiring_domains, expiring_ssl

def build_html_email(expiring_domains, expiring_ssl):
    # Similar to what you already have
    ...

def send_expiry_report_email():
    with app.app_context():  # Ensure Flask app context is available
        expiring_domains, expiring_ssl = get_expiring_domains_and_ssl()
        if not expiring_domains and not expiring_ssl:
            print("No expiring domains or SSL certificates found.")
            return

        html_content = build_html_email(expiring_domains, expiring_ssl)

        email_body_file = "/cert-monitor/expiry_report.html"
        with open(email_body_file, 'w') as f:
            f.write(html_content)

        email_subject = build_email_subject(expiring_domains, expiring_ssl)
        send_email("brian.cox@avispl.com", email_subject, email_body_file)

def build_email_subject(expiring_domains, expiring_ssl):
    # Similar to what you already have
    ...

# Main loop
if __name__ == "__main__":
    while not shutdown_flag:
        with app.app_context():  # Ensure Flask app context is available
            update_expiry_data()

        # Check if the email has been sent today
        if not has_email_been_sent_today():
            send_expiry_report_email()
            mark_email_as_sent_today()

        # Sleep for the interval, checking for SIGTERM
        for _ in range(60 * UPDATE_INTERVAL):
            if shutdown_flag:
                break
