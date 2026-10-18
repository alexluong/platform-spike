-- One Postgres for stack f, one database per component. Logto's seed creates
-- its own database (`logto`) and roles on first start.
CREATE DATABASE spicedb;
CREATE DATABASE app;
