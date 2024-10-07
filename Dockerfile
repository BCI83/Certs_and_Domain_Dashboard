FROM python:3.10-slim

# Install required packages, including supervisor for process management
RUN apt-get update && apt-get install -y curl iputils-ping dnsutils whois sendmail mailutils supervisor

# Set up the working directory
WORKDIR /cert-monitor

# Copy the application code into the container
COPY . /cert-monitor

# Install Python dependencies
RUN pip --default-timeout=100 install --no-cache-dir -r /cert-monitor/requirements.txt

# Expose the application port
EXPOSE 54321

# Copy the supervisor configuration file
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Use supervisord to run both sendmail and gunicorn
CMD ["/usr/bin/supervisord"]

