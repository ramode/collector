FROM alpine
ADD . /code
WORKDIR /code
RUN apk update \
  && apk add libuv libpq \
  && apk add --virtual build-deps gcc musl-dev make libuv-dev postgresql-dev pkgconfig \
  && make install \
  && apk del build-deps && ls -la /usr/local/bin/collector
CMD ["collector"]
