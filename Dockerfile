FROM python:3.10-slim

RUN apt-get update && apt-get install -y curl iputils-ping dnsutils whois mailutils

# Configure Postfix to send emails without local domain handling
RUN echo "relayhost = " >> /etc/postfix/main.cf

# Create /etc/mailname file and populate it with certificate.monitor
RUN echo "certificate.monitor" > /etc/mailname

WORKDIR /cert-monitor

COPY . /cert-monitor

RUN pip --default-timeout=100 install --no-cache-dir -r /cert-monitor/requirements.txt

EXPOSE 54321

ENV FLASK_APP=cert-monitor.py

CMD ["gunicorn", "-w", "25", "-b", "0.0.0.0:54321", "cert-monitor:app"]
