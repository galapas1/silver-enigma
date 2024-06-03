$ brew install postgresql
$ brew services start postgresql

$ psql postgres
CREATE DATABASE ninjapanda;
CREATE ROLE ninjaadmin WITH LOGIN PASSWORD 'n1nj@@dm1n';
ALTER ROLE ninjaadmin CREATEDB;

-- psql postgres -U ninjaadmin

$ apt-get install pgloader
or
$ brew install pgloader
