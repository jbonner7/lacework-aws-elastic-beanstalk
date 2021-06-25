# Use Alpine as base
FROM alpine:latest

# Maintainer
MAINTAINER andreas@lacework.net

# Copy the Lacework agent sidecar files
COPY lacework-backup /var/lib/lacework-backup

# Create the Lacework agent configuration
RUN mkdir -p /var/lib/lacework/config && \
echo '{ "tokens": {"accesstoken":"<YOUR-AGENT-TOKEN>"}, "serverurl": "https://api.fra.lacework.net"}' > /var/lib/lacework/config/config.json

# Copy the run script for the python start
COPY run.sh /usr/bin/run.sh

# Make it executable
RUN chmod +x /usr/bin/run.sh

# Updating apk
RUN apk update && apk upgrade

# Install python and pip
RUN apk add py3-pip
RUN apk add python3

# Upgrade pip
RUN pip install --upgrade pip

# Install Python modules needed by the Python app
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt

# Copy files required for the app to run
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/

# Expose the app on Flask default (5000)
EXPOSE 5000

# Run the application
CMD ["sh", "-c", "/var/lib/lacework-backup/lacework-sidecar.sh && /usr/bin/run.sh"]
#CMD ["/usr/bin/run.sh"]
#CMD ["python", "/usr/src/app/app.py"]
