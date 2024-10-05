from cert_monitor import get_certificate_expiry, get_whois_expiry, db, Domain, Subdomain, app
import datetime
import os
import pytz
import time

# Get update interval from environment variables (default to 60 minutes)
UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL', 60))
print("starting 1 minute cycle")
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
                print(f"Updating WHOIS expiry for {domain.domain_name}...")
                # Check and update WHOIS expiry for the domain
                whois_expiry = get_whois_expiry(domain.domain_name)
                if whois_expiry:
                    domain.whois_expiry = whois_expiry
                    domain.last_update = now_utc  # Update with the current UTC time
                    print(f"Updated WHOIS expiry for {domain.domain_name} at {now_utc}")

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
                        print(f"Updating certificate expiry for {subdomain.subdomain_name}...")
                        # Check and update certificate expiry for the subdomain
                        expiry_date, verification_status = get_certificate_expiry(subdomain.subdomain_name)
                        if expiry_date:
                            subdomain.expiry_date = expiry_date
                            subdomain.verification_status = verification_status
                            subdomain.last_update = now_utc  # Update with the current UTC time
                            print(f"Updated certificate expiry for {subdomain.subdomain_name} at {now_utc}")

        # Commit updates to the database
        db.session.commit()

if __name__ == "__main__":
    while True:
        update_expiry_data()
        time.sleep(60)  # Sleep for 1 minute before checking again
