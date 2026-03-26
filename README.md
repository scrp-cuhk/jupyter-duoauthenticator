# Duo Authenticator for JupyterHub

A JupyterHub authenticator that adds Duo two-factor authentication as a secondary
authentication layer on top of primary authentication (PAM by default).

## Features

- **Two authentication modes:**
  - **Universal mode** (default): Uses Duo Universal Prompt with OAuth-based redirect flow
  - **Auth API mode**: Uses Duo Auth API for legacy credentials (ikey/skey) with device selection UI

- **User mapping**: Map JupyterHub usernames to different Duo usernames via CSV file

- **Per-user bypass**: Allow specific users to skip Duo authentication

- **Flexible configuration**: Configure via JupyterHub config or environment variables

## Requirements

This plugin adds Duo **secondary authentication**. Primary authentication is done
using another Authenticator (PAMAuthenticator by default).

Test that your primary authenticator works before installing this plugin.

## Installation

```bash
pip install git+https://github.com/scrp-cuhk/jupyter-duoauthenticator.git
```

Or install from a local checkout:

```bash
git clone https://github.com/scrp-cuhk/jupyter-duoauthenticator.git
cd jupyter-duoauthenticator
pip install -e .
```

## Configuration

Enable the authenticator in your `jupyterhub_config.py`:

```python
c.JupyterHub.authenticator_class = 'duoauthenticator.DuoAuthenticator'
```

### Duo Universal Mode (Default)

Create a "Universal Prompt" application in the Duo Admin Panel and configure:

```python
c.DuoAuthenticator.duo_mode = 'universal'  # this is the default
c.DuoAuthenticator.client_id = 'DIXXXXXXXX'
c.DuoAuthenticator.client_secret = 'xxxxxxxxxx'
c.DuoAuthenticator.apihost = 'api-xxxxx.duosecurity.com'
c.DuoAuthenticator.redirect_uri = 'https://your-jupyterhub.example.com/hub/duo-callback'
```

### Duo Auth API Mode (Legacy Credentials)

For legacy Duo credentials (ikey/skey from a "Web SDK" or "Auth API" integration):

```python
c.DuoAuthenticator.duo_mode = 'auth_api'
c.DuoAuthenticator.auth_api_ikey = 'DIXXXXXXXX'
c.DuoAuthenticator.auth_api_skey = 'xxxxxxxxxx'
c.DuoAuthenticator.apihost = 'api-xxxxx.duosecurity.com'
```

Auth API mode provides a device selection UI showing enrolled devices with their
capabilities (push, phone, SMS, passcode).

## User Mapping

Map JupyterHub usernames to different Duo usernames via a CSV file.

### Configuration

```python
c.DuoAuthenticator.duo_user_list_path = '/path/to/duo-user-list.csv'
```

Or via environment variable:

```bash
export DUO_USER_LIST=/path/to/duo-user-list.csv
```

### CSV Format

```csv
username,duo_username,bypass
juser,juser.duo,0
admin,admin.duo,1
testuser,465977,No
```

| Field | Description |
|-------|-------------|
| `username` | JupyterHub login username |
| `duo_username` | Duo username to authenticate against |
| `bypass` | Set to `1` to skip Duo for this user, `0` or `No` otherwise |

### Default Behavior for Unknown Users

Control what happens for users not in the mapping file:

```python
# Require Duo for unknown users (default)
c.DuoAuthenticator.duo_default_bypass = False

# Allow unknown users to bypass Duo
c.DuoAuthenticator.duo_default_bypass = True
```

Or via environment variable:

```bash
export DUO_DEFAULT_BYPASS=true
```

### Cache Behavior

The user mapping is cached with a TTL (time-to-live) to balance performance
with update responsiveness:

```python
# Reload mapping every 60 seconds (default)
c.DuoAuthenticator.duo_user_list_cache_ttl = '60'

# Disable caching - reload on every login
c.DuoAuthenticator.duo_user_list_cache_ttl = '0'
```

If the mapping file becomes inaccessible after initial load, the cached
mapping is retained until the file becomes available again. This ensures
logins continue working during temporary file system issues.

## Configuration Reference

### Required Options

| Option | Description |
|--------|-------------|
| `client_id` | Duo Client ID (Universal mode) |
| `client_secret` | Duo Client Secret (Universal mode) |
| `redirect_uri` | OAuth callback URL (Universal mode) |
| `auth_api_ikey` | Duo Integration Key (Auth API mode) |
| `auth_api_skey` | Duo Secret Key (Auth API mode) |
| `apihost` | Duo API hostname (e.g., `api-xxxxx.duosecurity.com`) |

### Optional Options

| Option | Default | Description |
|--------|---------|-------------|
| `duo_mode` | `'universal'` | Authentication mode: `'universal'` or `'auth_api'` |
| `duo_user_list_path` | `''` | Path to user mapping CSV file |
| `duo_default_bypass` | `False` | Bypass Duo for users not in mapping file |
| `duo_user_list_cache_ttl` | `'60'` | Cache TTL in seconds for user mapping (0 to disable) |
| `auth_api_timeout` | `'300'` | Session timeout in seconds (Auth API mode) |
| `primary_auth_class` | `PAMAuthenticator` | Primary authentication class |

## Environment Variables

| Variable | Equivalent Config |
|----------|-------------------|
| `DUO_USER_LIST` | `duo_user_list_path` |
| `DUO_DEFAULT_BYPASS` | `duo_default_bypass` (set to `1`, `true`, or `yes`) |

## Example Configuration

```python
# jupyterhub_config.py

c.JupyterHub.authenticator_class = 'duoauthenticator.DuoAuthenticator'

# Auth API mode with legacy credentials
c.DuoAuthenticator.duo_mode = 'auth_api'
c.DuoAuthenticator.auth_api_ikey = 'DIXXXXXXXX'
c.DuoAuthenticator.auth_api_skey = 'xxxxxxxxxx'
c.DuoAuthenticator.apihost = 'api-xxxxx.duosecurity.com'

# User mapping
c.DuoAuthenticator.duo_user_list_path = '/etc/jupyterhub/duo-users.csv'

# Unknown users require Duo
c.DuoAuthenticator.duo_default_bypass = False
```

## License

GPLv3
