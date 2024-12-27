FROM python:3.10-slim

# Install required packages including Postfix
RUN apt-get update && apt-get install -y curl iputils-ping dnsutils whois postfix mailutils postgresql-client

# Set up the working directory
WORKDIR /cert-monitor

# Copy the application code into the container
COPY . /cert-monitor

# Configure Postfix to send emails without local domain handling
RUN echo "relayhost = " >> /etc/postfix/main.cf

# Create /etc/mailname file and populate it with certificate.monitor
RUN echo "certificate.monitor" > /etc/mailname

# Install Python dependencies (if any)
RUN pip --default-timeout=100 install --no-cache-dir -r /cert-monitor/requirements.txt

# Expose the port for your Flask app
EXPOSE 80

# Start Postfix and the Flask app when the container starts
CMD service postfix start && gunicorn -w 5 -b 0.0.0.0:80 cert_monitor:app
