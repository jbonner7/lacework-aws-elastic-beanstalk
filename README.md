# lacework-aws-elastic-beanstalk
Repository with examples how to integrate the Lacework agent into AWS Elastic Beanstalk by using the Docker running on 64bit Amazon Linux 2.

# Installation Lacework Agent as systemd service on the node.

Inside the folder sayhello you will find a simple Docker application example that uses NGINX and a simple index.html webpage. The protection via Lacework is done via the installation of the Lacework as a systemd service that is configured with the sayhello/.ebextensions/lacework.config file. Please make sure you configure your AGENT ACCESS TOKEN within <YOUR-AGENT-TOKEN> of the lacework.config before you create the app in Elastic Beanstalk.

# Installation Lacework Agent as Docker Container on the node.

Inside the folder my-tweet-app you will find a simple Docker application application using Python Flask to run a simple web application showing different gif pictures. The protection via Lacework is configured with the Lacework agent installed as a docker container running on the ec2 instance of Elastic Beanstalk that is configured with the my-tweet-app/.ebextensions/lacework.config file. Please make sure you configure your AGENT ACCESS TOKEN with <YOUR-AGENT-TOKEN> of the lacework.config before you create the app in Elastic Beanstalk.

# Installation Lacework Agent inside the Container

Inside the folder my-tweet-app-insidecontainer you will find a simple Docker application application using Python Flask to run a simple web application showing different gif pictures. The protection via Lacework is configured with the Lacework agent running inside the same container as the python flask application that is configured with the my-tweet-app-insidecontainer/Dockerfile file. Please make sure you configure your AGENT ACCESS TOKEN with <YOUR-AGENT-TOKEN> of the Dockerfile before you create the app in Elastic Beanstalk.
