# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d AS build
WORKDIR /source/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --include=dev
COPY web ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:stable-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
ARG SOURCE_COMMIT
RUN test "${#SOURCE_COMMIT}" = 40 && \
    case "$SOURCE_COMMIT" in *[!0-9a-f]*) exit 1;; esac
LABEL org.opencontainers.image.source="https://github.com/amliuyong/a-auth" \
      org.opencontainers.image.revision="$SOURCE_COMMIT" \
      org.opencontainers.image.title="a-auth browser pages"
COPY deploy/containers/web.nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=65532:65532 /source/web/dist /usr/share/nginx/html
USER 65532:65532
EXPOSE 8083
STOPSIGNAL SIGQUIT
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
