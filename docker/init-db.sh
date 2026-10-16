#!/bin/sh
# Cria os dois papéis do banco: DONO (migrações) e APLICAÇÃO (runtime, sujeito a RLS).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE imovel_owner LOGIN PASSWORD '${OWNER_DB_PASSWORD}';
CREATE ROLE imovel_app LOGIN PASSWORD '${APP_DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE imoveladmin OWNER imovel_owner;
REVOKE ALL ON DATABASE imoveladmin FROM PUBLIC;
GRANT CONNECT ON DATABASE imoveladmin TO imovel_app;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname imoveladmin <<SQL
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
