FROM python:3.10-slim

# Install required packages including Postfix for email sending
RUN apt-get update && apt-get install -y curl iputils-ping dnsutils whois postfix mailutils

# Configure Postfix to send emails without local domain handling
RUN echo "relayhost = " >> /etc/postfix/main.cf

# Set up the working directory
WORKDIR /cert-monitor

# Copy the application code into the container
COPY . /cert-monitor

# Install Python dependencies (if any)
RUN pip --default-timeout=100 install --no-cache-dir -r /cert-monitor/requirements.txt

# Expose the port for your Flask app
EXPOSE 54321

# Start Postfix and the Flask app when the container starts
CMD service postfix start && gunicorn -w 25 -b 0.0.0.0:54321 cert_monitor:app
