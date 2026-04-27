# Membership Management System (PHP/MySQL)

A PHP/MySQL membership management system with Docker support for one-command deployment.

## Source

Original project from [CodeAstro](https://codeastro.com/download/membership-management-system-project-in-php-mysql-with-source-code/).

Developed by CodeAstro. Recommended PHP Version 7.

## Quick Start

```bash
docker compose up -d --build
```

The application will be available at **http://localhost:9010**.

### Default Login

| Field    | Value            |
|----------|------------------|
| Email    | admin@mail.com   |
| Password | codeastro.com    |

## Stop

```bash
docker compose down
```

To also remove the database volume:

```bash
docker compose down -v
```

## Project Structure

```
├── includes/           # PHP config, header, footer, sidebar, nav
├── plugins/            # AdminLTE, jQuery, Bootstrap, DataTables
├── dist/               # CSS/JS assets
├── uploads/            # Member photos and logo
├── DATABASE FILE/      # Original SQL dump
├── docker/mysql/       # Docker init SQL
├── Dockerfile
├── docker-compose.yml
└── *.php               # Application pages
```
