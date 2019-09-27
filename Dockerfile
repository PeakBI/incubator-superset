FROM python:3.6-jessie

RUN useradd --user-group --create-home --no-log-init --shell /bin/bash superset

# Configure environment
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update -y

# Install dependencies to fix `curl https support error` and `elaying package configuration warning`
RUN apt-get install -y apt-transport-https apt-utils


# Install superset dependencies
# https://superset.incubator.apache.org/installation.html#os-dependencies
RUN apt-get install -y build-essential libssl-dev \
    libffi-dev python3-dev libsasl2-dev libldap2-dev libxi-dev

# Install extra useful tool for development
RUN apt-get install -y vim less postgresql-client redis-tools

# Install nodejs for custom build
# https://superset.incubator.apache.org/installation.html#making-your-own-build
# https://nodejs.org/en/download/package-manager/
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash - \
    && apt-get install -y nodejs


ARG SUPERSET_ENV=$SUPERSET_ENV
ARG SQLALCHEMY_DATABASE_URI=$SQLALCHEMY_DATABASE_URI
ARG TENANT=$TENANT
ARG STAGE=$STAGE
ARG REDIS_ENDPOINT=$REDIS_ENDPOINT
ARG SQLALCHEMY_ENGINE_OPTIONS=$SQLALCHEMY_ENGINE_OPTIONS
ARG ADMIN_EMAIL=$ADMIN_EMAIL
ARG ADMIN_PASSWORD=$ADMIN_PASSWORD
ARG GUEST_EMAIL=$GUEST_EMAIL
ARG GUEST_PASSWORD=$GUEST_PASSWORD
ARG AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION

ENV SUPERSET_ENV=${SUPERSET_ENV} \
  SQLALCHEMY_DATABASE_URI=${SQLALCHEMY_DATABASE_URI} \
  TENANT=${TENANT} \
  STAGE=$STAGE \
  REDIS_ENDPOINT=${REDIS_ENDPOINT} \
  SQLALCHEMY_ENGINE_OPTIONS=${SQLALCHEMY_ENGINE_OPTIONS} \
  ADMIN_EMAIL=${ADMIN_EMAIL} \
  ADMIN_PASSWORD=${ADMIN_PASSWORD} \
  GUEST_EMAIL=${GUEST_EMAIL} \
  GUEST_PASSWORD=${GUEST_PASSWORD} \
  AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}

WORKDIR /home/superset

COPY . /home/superset

RUN pip install --upgrade setuptools pip \
  && pip install -r requirements.txt -r requirements-dev.txt  \
  && pip install -e . \
  && pip install gevent \
  && rm -rf /root/.cache/pip

RUN cd superset/assets \
  && npm ci \
  && npm run build \
  && rm -rf node_modules

RUN chmod +x docker_init.sh && ./docker_init.sh

RUN chmod +x docker_entrypoint.sh

EXPOSE 8088

CMD ["./docker_entrypoint.sh"]
