FROM postgres:17-alpine
COPY init.sql /docker-entrypoint-initdb.d/init.sql
# Not an init script: run by the f-logto-seed one-shot after Logto has created its schema.
COPY logto-seed.sql /seed/logto-seed.sql
