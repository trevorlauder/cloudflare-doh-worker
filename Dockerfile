FROM node:18-slim

RUN apt update && \
    apt install -y --no-install-recommends ca-certificates libc++-dev && \
    apt clean

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci

COPY . .

ENV NODE_OPTIONS --openssl-legacy-provider

EXPOSE 8080
CMD [ "/usr/src/app/entrypoint.sh" ]
