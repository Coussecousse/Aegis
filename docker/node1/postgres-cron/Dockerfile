FROM alpine:3.20

RUN apk add --no-cache postgresql16-client

COPY cleanup.sh /cleanup.sh
RUN chmod +x /cleanup.sh

# Setup crontab (busybox crond is included in alpine by default)
RUN echo "0 3 * * * /cleanup.sh >> /proc/1/fd/1 2>&1" > /etc/crontabs/root

CMD ["crond", "-f", "-l", "2"]
