
FROM centos:7
LABEL maintainer="Tristan Landès"
RUN yum -y install ruby@2.7
RUN yum install -y make gcc ruby-devel libxml2 libxml2-devel libxslt libxslt-devel
RUN gem install wpscan
RUN yum -y install python3
COPY . /wpwatcher
WORKDIR /wpwatcher
RUN python3 ./setup install
RUN adduser -h /wpwatcher -g WPWatcher -D wpwatcher
RUN chown -R wpwatcher:wpwatcher /wpwatcher
USER wpwatcher
ENTRYPOINT ["python3 ./wpwatcher.py"]
