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

def update_expiry_data():
    with app.app_context():  # Ensure Flask app context is available
        now_utc = datetime.datetime.now(pytz.UTC)  # Current UTC time (aware)
        update_threshold = now_utc - datetime.timedelta(minutes=UPDATE_INTERVAL)

#        print(f"Update threshold: {update_threshold}, Current time: {now_utc}")

        # Fetch all domains
        all_domains = Domain.query.all()

        for domain in all_domains:
            # Ensure last_update is timezone-aware (in UTC) before comparing
            if domain.last_update is not None:
                if domain.last_update.tzinfo is None:  # If naive, make it aware in UTC
                    domain_last_update = domain.last_update.replace(tzinfo=pytz.UTC)
                else:
                    domain_last_update = domain.last_update
            else:
                domain_last_update = None

            # Log the comparison
#            print(f"Domain: {domain.domain_name}, Last update: {domain_last_update}")

            # Update domain only if it hasn't been updated in the last UPDATE_INTERVAL
            if domain_last_update is None or domain_last_update < update_threshold:
                # Set `now_utc` for each individual update
                now_utc = datetime.datetime.now(pytz.UTC)
#                print(f"Updating WHOIS expiry for {domain.domain_name}...")
                # Check and update WHOIS expiry for the domain
                whois_expiry = get_whois_expiry(domain.domain_name)
                if whois_expiry:
                    domain.whois_expiry = whois_expiry
                    domain.last_update = now_utc  # Update with the current UTC time
#                    print(f"Updated WHOIS expiry for {domain.domain_name} at {now_utc}")

                # Get subdomains for the domain
                subdomains = Subdomain.query.filter_by(domain_id=domain.id).all()

                for subdomain in subdomains:
                    # Ensure last_update for subdomain is timezone-aware (in UTC) before comparing
                    if subdomain.last_update is not None:
                        if subdomain.last_update.tzinfo is None:  # If naive, make it aware in UTC
                            subdomain_last_update = subdomain.last_update.replace(tzinfo=pytz.UTC)
                        else:
                            subdomain_last_update = subdomain.last_update
                    else:
                        subdomain_last_update = None

                    # Log the comparison for subdomains
#                    print(f"Subdomain: {subdomain.subdomain_name}, Last update: {subdomain_last_update}")

                    # Update subdomain only if it hasn't been updated in the last UPDATE_INTERVAL
                    if subdomain_last_update is None or subdomain_last_update < update_threshold:
                        # Set `now_utc` for each individual update
                        now_utc = datetime.datetime.now(pytz.UTC)
#                        print(f"Updating certificate expiry for {subdomain.subdomain_name}...")
                        # Check and update certificate expiry for the subdomain
                        expiry_date, verification_status = get_certificate_expiry(subdomain.subdomain_name)
                        if expiry_date:
                            subdomain.expiry_date = expiry_date
                            subdomain.verification_status = verification_status
                            subdomain.last_update = now_utc  # Update with the current UTC time
#                            print(f"Updated certificate expiry for {subdomain.subdomain_name} at {now_utc}")

        # Commit updates to the database
        db.session.commit()

def send_email(to_address, subject, body_file, from_address="Symphony Certificate and Domain Monitor <admin@certificate.monitor>"):
    command = f'mail -s "{subject}" -a "From: {from_address}" {to_address} < {body_file}'
    try:
        # Execute the mail command
        subprocess.run(command, shell=True, check=True)
        print(f"Email sent to {to_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to send email: {e}")

def has_email_been_sent_today():
    if os.path.exists(LAST_EMAIL_SENT_FILE):
        try:
            with open(LAST_EMAIL_SENT_FILE, 'r') as f:
                last_sent_str = f.read().strip()
                if last_sent_str:  # Ensure the file is not empty
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

def get_expiring_domains_and_ssl():
    now_utc = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    thirty_days_from_now = now_utc + datetime.timedelta(days=30)

    # Get domains expiring within the next 30 days
    expiring_domains = Domain.query.filter(Domain.whois_expiry.isnot(None), Domain.whois_expiry <= thirty_days_from_now).all()

    # Get subdomains (SSL certs) expiring within the next 30 days
    expiring_ssl = Subdomain.query.filter(Subdomain.expiry_date.isnot(None), Subdomain.expiry_date <= thirty_days_from_now).all()

    return expiring_domains, expiring_ssl

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
            }
            th {
                background-color: #f2f2f2;
            }
            .orange {
                color: orange;
            }
            .red {
                color: red;
            }
        </style>
    </head>
    <body>
        <h2>Expiry Report</h2>
    """

    # Add domains
    html_content += "<h3>Domain Expiries</h3>"
    if expiring_domains:
        html_content += "<table><tr><th>Domain</th><th>WHOIS Expiry Date</th></tr>"
        for domain in expiring_domains:
            days_to_expiry = (domain.whois_expiry - datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)).days
            if days_to_expiry < 7:
                row_class = "red"
            else:
                row_class = "orange"

            html_content += f"<tr class='{row_class}'><td>{domain.domain_name}</td><td>{domain.whois_expiry}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No domains are expiring in the next 30 days.</p>"

    # Add SSL certificates
    html_content += "<h3>SSL Expiries</h3>"
    if expiring_ssl:
        html_content += "<table><tr><th>Subdomain</th><th>SSL Expiry Date</th></tr>"
        for subdomain in expiring_ssl:
            days_to_expiry = (subdomain.expiry_date - datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)).days
            if days_to_expiry < 7:
                row_class = "red"
            else:
                row_class = "orange"

            html_content += f"<tr class='{row_class}'><td>{subdomain.subdomain_name}</td><td>{subdomain.expiry_date}</td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p>No SSL certificates are expiring in the next 30 days.</p>"

    html_content += "</body></html>"

    return html_content

def send_expiry_report_email():
    expiring_domains, expiring_ssl = get_expiring_domains_and_ssl()
    if not expiring_domains and not expiring_ssl:
        print("No expiring domains or SSL certificates found.")
        return  # No need to send an email if there's nothing expiring

    # Build the HTML email content
    html_content = build_html_email(expiring_domains, expiring_ssl)

    # Save the HTML content to a file
    email_body_file = "/cert-monitor/expiry_report.html"
    with open(email_body_file, 'w') as f:
        f.write(html_content)

    # Dynamically build the email subject
    email_subject = build_email_subject(expiring_domains, expiring_ssl)

    # Send the email
    send_email("brian.cox@avispl.com", email_subject, email_body_file, from_address="Symphony Certificate and Domain Monitor <admin@certificate.monitor>")

def get_expiration_urgency(expiring_items):
    """
    Returns the urgency of the expirations: 
    'urgent' if less than 7 days, 'warning' if between 7 and 30 days.
    """
    now_utc = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    most_urgent = 30  # Default to max 30 days
    
    for item in expiring_items:
        expiry_date = item.whois_expiry if hasattr(item, 'whois_expiry') else item.expiry_date
        days_to_expiry = (expiry_date - now_utc).days
        most_urgent = min(most_urgent, days_to_expiry)
    
    if most_urgent < 7:
        return 'urgent'
    else:
        return 'warning'
    
def build_email_subject(expiring_domains, expiring_ssl):
    """
    Constructs the subject line dynamically based on the types of expirations 
    and their urgency.
    """
    if not expiring_domains and not expiring_ssl:
        return "No Expiries Today"  # If there's nothing expiring, no need to send

    urgency_level = "warning"
    if expiring_domains:
        urgency_level = get_expiration_urgency(expiring_domains)
    if expiring_ssl:
        urgency_level = get_expiration_urgency(expiring_ssl) if urgency_level == "warning" else urgency_level

    # Dynamically adjust the subject based on the type of expiring items
    subject = "[Certificate Monitor] "
    if expiring_domains and expiring_ssl:
        subject += f"Domain and SSL Expiries ({'URGENT' if urgency_level == 'urgent' else 'Expiring Soon'})"
    elif expiring_domains:
        subject += f"Domain Expiries ({'URGENT' if urgency_level == 'urgent' else 'Expiring Soon'})"
    elif expiring_ssl:
        subject += f"SSL Certificate Expiries ({'URGENT' if urgency_level == 'urgent' else 'Expiring Soon'})"
    
    return subject

if __name__ == "__main__":
    while not shutdown_flag:
        update_expiry_data()

        # Check if the email has been sent today
        if not has_email_been_sent_today():
            # Generate and send the expiry report email
            send_expiry_report_email()
            mark_email_as_sent_today()  # Mark that the email has been sent

        # Sleep in small increments to handle SIGTERM quickly
        for _ in range(60 * UPDATE_INTERVAL):  # Sleep for UPDATE_INTERVAL minutes, checking every second
            if shutdown_flag:
                break