FROM nginx:1.29-alpine
# The entrypoint renders templates/*.template into conf.d with envsubst (LOGTO_PUBLIC_HOST).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
