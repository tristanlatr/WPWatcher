# WPWatcher Dockerfile
FROM ruby:alpine
# Install dependencies
RUN apk --update add --virtual build-dependencies ruby-dev build-base &&\
    apk --update add curl &&\
    apk --update add git
# Install WPScan lastest tested version
RUN gem install wpscan -v 3.7.11
# Python install from frolvlad/alpine-python3
# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1
RUN echo "**** install Python ****" && \
    apk add --no-cache python3 && \
    if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi 
# Init folder tree
RUN mkdir /wpwatcher && mkdir /wpwatcher/.wpwatcher
# Add scripts repo
ADD setup.py /wpwatcher
ADD wpwatcher.py /wpwatcher
ADD wpscan_parser.py /wpwatcher
WORKDIR /wpwatcher
# Install
RUN python ./setup.py install
# Setup user and group
RUN adduser -h /wpwatcher -g WPWatcher -D wpwatcher
RUN chown -R wpwatcher:wpwatcher /wpwatcher
USER wpwatcher
# Run command
WORKDIR /
ENTRYPOINT ["wpwatcher"]
