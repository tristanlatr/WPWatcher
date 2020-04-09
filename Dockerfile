
FROM centos:8
LABEL maintainer="Tristan Landès"
RUN yum install ruby
RUN gem install wpscan
RUN yum install python3
RUN python3 ./setup install

# RUN chmod -R a+r /usr/local/bundle

RUN adduser -h /wpwatcher -g WPWatcher -D wpwatcher
COPY ./wpwatcher.conf /wpwatcher/
RUN chown -R wpwatcher:wpwatcher /wpwatcher

# runtime dependencies
# RUN apk add --no-cache libcurl procps sqlite-libs

WORKDIR /wpwatcher
USER wpwatcher
ENTRYPOINT ["/usr/local/bin/wpwatcher"]