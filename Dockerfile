FROM node:22-slim

RUN apt update && \
    apt install -y --no-install-recommends ca-certificates libc++-dev tini && \
    apt clean

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci

COPY . .

ENV NODE_OPTIONS=--openssl-legacy-provider

EXPOSE 8080

ENTRYPOINT ["tini", "--"]
CMD [ "/usr/src/app/entrypoint.sh" ]
