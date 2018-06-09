FROM ubuntu:latest

# Install dependencies
RUN apt-get update \
 && apt-get install -y ruby ruby-dev build-essential gcc curl python-pip git sudo curl ssh \
 && gem install fpm \

WORKDIR /workspace