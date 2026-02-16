# LocalDocsMD

A self-hosted documentation workspace for Markdown files with multi-user support and role-based access control.

## Features

- **Workspaces & Projects** - Organize documentation into workspaces containing multiple projects
- **Markdown Rendering** - Full Markdown support with syntax highlighting
- **Multi-User** - User management with admin and user roles
- **Role-Based Access** - Users can have different access levels per workspace
- **Password Management** - Admin-approved password change workflow
- **No External Dependencies** - Single binary with embedded web server

## Quick Start

```bash
# Build
mkdir build && cd build
cmake ..
make

# Run
./localdocsmd
```

Open http://localhost:8080 in your browser.

**Default credentials:** `admin` / `admin`

You will be required to change the password on first login.

## Configuration

Copy `config.ini.example` to `config.ini` and edit as needed:

```ini
[server]
host = 0.0.0.0
port = 8080

[security]
session_timeout = 86400
password_min_length = 8
secret_key = change_this_secret_key_in_production

[admin]
default_username = admin
default_email = admin@localhost
```

## Built With

- [Mongoose](https://mongoose.ws/) - Embedded HTTP server
- [SQLite](https://sqlite.org/) - Database
- [md4c](https://github.com/mity/md4c) - Markdown parser
- [cJSON](https://github.com/DaveGamble/cJSON) - JSON library

## License

MIT
