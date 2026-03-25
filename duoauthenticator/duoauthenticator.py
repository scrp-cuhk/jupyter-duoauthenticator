from jupyterhub.auth import Authenticator, PAMAuthenticator
from jupyterhub.handlers import LoginHandler, BaseHandler
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Type, Instance, default, Bool, List
import duo_universal
import csv
import os
import secrets
import time
import json
import sys
from urllib.parse import urlparse, urlunparse

class DuoHandler(LoginHandler):
    """Duo Universal Two-Factor Handler"""

    async def post(self):
        """Override the default POST handler for Duo Universal authentication.
        Handles login form submissions - redirects to Duo for 2FA after primary auth.
        """
        # parse the arguments dict
        data = {}
        for arg in self.request.arguments:
            data[arg] = self.get_argument(arg, strip=False)

        # Do primary auth
        duo_username = await self.authenticator.do_primary_auth(self, data)

        if duo_username:
            # Check if user should bypass Duo
            if self.authenticator._current_bypass:
                # Bypass Duo, authenticate user with primary auth only
                self.log.info("Bypassing Duo for user '%s'", self.authenticator._current_auth_username)
                # Get the authenticated result from primary auth
                authenticated = self.authenticator._current_user
                if authenticated:
                    # Convert to User object and set login cookie
                    user = await self.auth_to_user(authenticated)
                    self.set_login_cookie(user)
                    self.redirect(self.get_next_url(user))
                else:
                    html = await self._render(
                        login_error='Authentication failed',
                        username='',
                    )
                    self.finish(html)
            else:
                # Perform Duo 2FA using Universal redirect flow
                try:
                    # Create Duo client
                    duo_client = duo_universal.Client(
                        self.authenticator.client_id,
                        self.authenticator.client_secret,
                        self.authenticator.apihost,
                        self.authenticator.redirect_uri
                    )

                    # Perform health check
                    duo_client.health_check()

                    # Generate state
                    state = duo_client.generate_state()

                    # Store state mapped to username for callback validation
                    self.authenticator._state_mapping[state] = duo_username

                    # Create auth URL and redirect to Duo
                    prompt_uri = duo_client.create_auth_url(duo_username, state)

                    self.log.debug("Redirecting user '%s' to Duo for authentication",
                        self.authenticator._current_auth_username)
                    self.redirect(prompt_uri)

                except duo_universal.DuoException as e:
                    self.log.error("Duo setup failed: %s", str(e))
                    html = await self._render(
                        login_error='Duo authentication unavailable',
                        username='',
                    )
                    self.finish(html)
        else:
            # self._render is defined by LoginHandler
            html = await self._render(
                login_error='Invalid username or password',
                username='',
            )
            self.finish(html)

class DuoCallbackHandler(BaseHandler):
    """Duo Universal Callback Handler"""

    async def get(self):
        """Handle Duo redirect callback with authorization code."""
        state = self.get_argument('state', default=None)
        code = self.get_argument('duo_code', default=None)

        if not state or not code:
            self.log.error("Duo callback missing required parameters")
            html = await self._render(
                login_error='Authentication failed: missing Duo response',
                username='',
            )
            self.finish(html)
            return

        # Validate state
        if state not in self.authenticator._state_mapping:
            self.log.error("Invalid OAuth state received from Duo")
            html = await self._render(
                login_error='Authentication failed: invalid state',
                username='',
            )
            self.finish(html)
            return

        # Get username from state mapping
        duo_username = self.authenticator._state_mapping[state]

        try:
            # Create Duo client and exchange code for 2FA result
            duo_client = duo_universal.Client(
                self.authenticator.client_id,
                self.authenticator.client_secret,
                self.authenticator.apihost,
                self.authenticator.redirect_uri
            )

            # Exchange authorization code for 2FA result
            decoded_token = duo_client.exchange_authorization_code_for_2fa_result(
                code,
                duo_username
            )

            # Clean up state
            self.authenticator._state_mapping.pop(state, None)

            self.log.debug("Duo authentication succeeded for user '%s'", duo_username)

            # Get the original auth username (may differ from duo_username)
            auth_username = None
            for username, info in self.authenticator._user_mapping.items():
                if info['duo_username'] == duo_username:
                    auth_username = username
                    break
            if auth_username is None:
                auth_username = duo_username  # No mapping found, use duo_username

            # Complete login flow
            authenticated = {'name': auth_username}
            user = await self.auth_to_user(authenticated)
            self.set_login_cookie(user)
            self.redirect(self.get_next_url(user))

        except duo_universal.DuoException as e:
            self.log.error("Duo authentication failed: %s", str(e))
            html = await self._render(
                login_error='Duo authentication failed',
                username='',
            )
            self.finish(html)


class DuoAuthAPIHandler(LoginHandler):
    """Duo Auth API Handler for legacy ikey/skey credentials"""

    def check_xsrf_cookie(self):
        """Override XSRF check - we use our own state token for CSRF protection."""
        # The 'state' parameter provides CSRF protection for our auth flow
        # We validate it in _handle_authenticate()
        return None

    def _render_custom_template(self, template_name, **kwargs):
        """Render a custom template from the package's template directory."""
        from jinja2 import Environment, FileSystemLoader

        # Find template directory
        template_dirs = self.authenticator.template_paths()
        if not template_dirs:
            self.log.error("Could not find template directory for %s", template_name)
            raise RuntimeError(f"Template directory not found")

        # Create Jinja2 environment with the template directories
        env = Environment(loader=FileSystemLoader(template_dirs))

        # Add len function to Jinja2 context
        kwargs['len'] = len

        # Add base_url if not provided
        if 'base_url' not in kwargs:
            kwargs['base_url'] = self.base_url

        template = env.get_template(template_name)
        return template.render(**kwargs)

    async def get(self):
        """Render login page or device selection page for Auth API mode."""
        state = self.get_argument('state', default=None)

        if not state:
            # No state means this is a regular login page request, render login form
            html = await self._render(username='')
            self.finish(html)
            return

        # Validate state exists in sessions
        session = self.authenticator._auth_sessions.get(state)
        if not session:
            self.log.error("Invalid or expired session state")
            html = await self._render(
                login_error='Authentication session expired. Please try again.',
                username='',
            )
            self.finish(html)
            return

        # Check session timeout
        timeout = int(self.authenticator.auth_api_timeout)
        if time.time() - session['timestamp'] > timeout:
            self.authenticator._auth_sessions.pop(state, None)
            self.log.error("Auth API session timed out")
            html = await self._render(
                login_error='Authentication session timed out. Please try again.',
                username='',
            )
            self.finish(html)
            return

        # Render device selection page
        html = self._render_custom_template(
            'duo_auth_api.html',
            state=state,
            devices=session.get('devices', []),
            duo_username=session.get('duo_username', ''),
            error=None
        )
        self.finish(html)

    async def post(self):
        """Handle Auth API authentication flow."""
        action = self.get_argument('action', default='login')

        if action == 'login':
            await self._handle_login()
        elif action == 'authenticate':
            await self._handle_authenticate()
        else:
            self.log.error("Unknown action: %s", action)
            html = await self._render(
                login_error='Invalid request',
                username='',
            )
            self.finish(html)

    async def _handle_login(self):
        """Handle initial login: primary auth + preauth API call."""
        # Parse form data
        data = {}
        for arg in self.request.arguments:
            data[arg] = self.get_argument(arg, strip=False)

        # Do primary auth
        duo_username = await self.authenticator.do_primary_auth(self, data)

        if not duo_username:
            html = await self._render(
                login_error='Invalid username or password',
                username='',
            )
            self.finish(html)
            return

        # Check if user should bypass Duo
        if self.authenticator._current_bypass:
            self.log.info("Bypassing Duo for user '%s'", self.authenticator._current_auth_username)
            authenticated = self.authenticator._current_user
            if authenticated:
                user = await self.auth_to_user(authenticated)
                self.set_login_cookie(user)
                self.redirect(self.get_next_url(user))
            else:
                html = await self._render(
                    login_error='Authentication failed',
                    username='',
                )
                self.finish(html)
            return

        # Call Duo preauth API to get devices
        try:
            import duo_client

            # Log configuration for debugging
            self.log.info("Duo Auth API mode - apihost: %s, ikey set: %s, skey set: %s",
                self.authenticator.apihost,
                bool(self.authenticator.auth_api_ikey),
                bool(self.authenticator.auth_api_skey))

            if not self.authenticator.auth_api_ikey or not self.authenticator.auth_api_skey:
                self.log.error("Duo Auth API credentials not configured")
                html = await self._render(
                    login_error='Duo Auth API credentials not configured. Set auth_api_ikey and auth_api_skey.',
                    username='',
                )
                self.finish(html)
                return

            auth_client = duo_client.Auth(
                ikey=self.authenticator.auth_api_ikey,
                skey=self.authenticator.auth_api_skey,
                host=self.authenticator.apihost
            )

            # Call preauth to get user's devices
            preauth_result = auth_client.preauth(username=duo_username)

            self.log.debug("Duo preauth result for '%s': %s", duo_username, preauth_result)

            # Check preauth result
            if preauth_result.get('result') == 'auth':
                # User can authenticate - get devices
                devices = preauth_result.get('devices', [])
                if not devices:
                    # Some accounts may have default device in response
                    devices = self._parse_default_device(preauth_result)

                # Generate state for this session
                state = secrets.token_urlsafe(32)

                # Store session data
                self.authenticator._auth_sessions[state] = {
                    'duo_username': duo_username,
                    'devices': devices,
                    'user': self.authenticator._current_user,
                    'auth_username': self.authenticator._current_auth_username,
                    'timestamp': time.time(),
                    'txid': None  # For async push polling
                }

                # Redirect to device selection page
                redirect_url = url_path_join(self.base_url, 'hub', 'duo-auth') + f"?state={state}"
                self.redirect(redirect_url)

            elif preauth_result.get('result') == 'allow':
                # User is allowed without 2FA (e.g., bypass policy)
                self.log.info("Duo preauth allowed user '%s' without 2FA", duo_username)
                authenticated = self.authenticator._current_user
                user = await self.auth_to_user(authenticated)
                self.set_login_cookie(user)
                self.redirect(self.get_next_url(user))

            elif preauth_result.get('result') == 'deny':
                # User is denied
                self.log.warning("Duo denied access for user '%s': %s",
                    duo_username, preauth_result.get('status_msg', 'No reason given'))
                html = await self._render(
                    login_error=preauth_result.get('status_msg', 'Access denied by Duo'),
                    username='',
                )
                self.finish(html)

            elif preauth_result.get('result') == 'enroll':
                # User needs to enroll
                self.log.info("User '%s' needs to enroll in Duo", duo_username)
                html = await self._render(
                    login_error='You must enroll in Duo two-factor authentication first.',
                    username='',
                )
                self.finish(html)

            else:
                # Unknown result
                self.log.error("Unknown Duo preauth result: %s", preauth_result)
                html = await self._render(
                    login_error='Duo authentication error. Please try again.',
                    username='',
                )
                self.finish(html)

        except Exception as e:
            self.log.error("Duo preauth failed: %s", str(e), exc_info=True)
            html = await self._render(
                login_error=f'Duo authentication error: {str(e)}',
                username='',
            )
            self.finish(html)

    def _parse_default_device(self, preauth_result):
        """Parse default device info if devices array is empty."""
        # Some Duo setups return device info differently
        devices = []

        # Check if there's a default device
        if 'devices' in preauth_result:
            return preauth_result['devices']

        # Check for single device in response
        if 'device' in preauth_result:
            devices = [{
                'device': preauth_result['device'],
                'display_name': preauth_result.get('device_name', 'Default Device'),
                'capabilities': preauth_result.get('capabilities', [])
            }]

        return devices

    async def _handle_authenticate(self):
        """Handle device selection and send auth request."""
        state = self.get_argument('state', default=None)
        device = self.get_argument('device', default=None)
        factor = self.get_argument('factor', default=None)
        passcode = self.get_argument('passcode', default=None)

        if not state:
            self.log.error("Missing state parameter")
            html = await self._render(
                login_error='Authentication error: missing state',
                username='',
            )
            self.finish(html)
            return

        # Get session
        session = self.authenticator._auth_sessions.get(state)
        if not session:
            self.log.error("Invalid or expired session state")
            html = await self._render(
                login_error='Authentication session expired. Please try again.',
                username='',
            )
            self.finish(html)
            return

        # Determine factor if not provided
        if not factor and passcode:
            factor = 'passcode'
        elif not factor:
            # Default to push
            factor = 'push'

        try:
            import duo_client

            auth_client = duo_client.Auth(
                ikey=self.authenticator.auth_api_ikey,
                skey=self.authenticator.auth_api_skey,
                host=self.authenticator.apihost
            )

            duo_username = session['duo_username']

            # Build auth parameters
            auth_params = {
                'username': duo_username,
                'factor': factor,
            }

            if device:
                auth_params['device'] = device
            if passcode:
                auth_params['passcode'] = passcode

            # Call auth API
            auth_result = auth_client.auth(**auth_params)

            self.log.debug("Duo auth result: %s", auth_result)

            if auth_result.get('result') == 'allow':
                # Authentication successful
                self.log.info("Duo auth succeeded for user '%s'", duo_username)

                # Clean up session
                self.authenticator._auth_sessions.pop(state, None)

                # Complete login
                authenticated = session['user']
                user = await self.auth_to_user(authenticated)
                self.set_login_cookie(user)
                self.redirect(self.get_next_url(user))

            elif auth_result.get('result') == 'waiting':
                # Async push - need to poll for status
                txid = auth_result.get('txid')
                if txid:
                    session['txid'] = txid
                    # Redirect to waiting page
                    redirect_url = url_path_join(self.base_url, 'hub', 'duo-waiting') + f"?state={state}"
                    self.redirect(redirect_url)
                else:
                    self.log.error("Duo auth waiting but no txid returned")
                    html = await self._render(
                        login_error='Duo authentication error. Please try again.',
                        username='',
                    )
                    self.finish(html)

            elif auth_result.get('result') == 'deny':
                # Authentication denied
                self.log.warning("Duo auth denied for user '%s': %s",
                    duo_username, auth_result.get('status_msg', 'No reason given'))

                # Re-render device selection with error
                html = self._render_custom_template(
                    'duo_auth_api.html',
                    state=state,
                    devices=session.get('devices', []),
                    duo_username=duo_username,
                    error=auth_result.get('status_msg', 'Authentication denied')
                )
                self.finish(html)

            else:
                # Unknown result
                self.log.error("Unknown Duo auth result: %s", auth_result)
                html = self._render_custom_template(
                    'duo_auth_api.html',
                    state=state,
                    devices=session.get('devices', []),
                    duo_username=duo_username,
                    error='Authentication error. Please try again.'
                )
                self.finish(html)

        except Exception as e:
            self.log.error("Duo auth failed: %s", str(e))
            session = self.authenticator._auth_sessions.get(state)
            if session:
                html = self._render_custom_template(
                    'duo_auth_api.html',
                    state=state,
                    devices=session.get('devices', []),
                    duo_username=session.get('duo_username', ''),
                    error='Authentication error. Please try again.'
                )
            else:
                html = await self._render(
                    login_error='Authentication error. Please try again.',
                    username='',
                )
            self.finish(html)


class DuoWaitingHandler(BaseHandler):
    """Handler for waiting page during async push authentication."""

    def _render_custom_template(self, template_name, **kwargs):
        """Render a custom template from the package's template directory."""
        from jinja2 import Environment, FileSystemLoader

        # Find template directory
        template_dirs = self.authenticator.template_paths()
        if not template_dirs:
            self.log.error("Could not find template directory for %s", template_name)
            raise RuntimeError(f"Template directory not found")

        # Create Jinja2 environment with the template directories
        env = Environment(loader=FileSystemLoader(template_dirs))

        # Add base_url if not provided
        if 'base_url' not in kwargs:
            kwargs['base_url'] = self.base_url

        template = env.get_template(template_name)
        return template.render(**kwargs)

    async def get(self):
        """Render waiting page for async push."""
        state = self.get_argument('state', default=None)

        if not state:
            self.log.error("Missing state parameter for waiting page")
            self.redirect(url_path_join(self.base_url, 'hub', 'login'))
            return

        session = self.authenticator._auth_sessions.get(state)
        if not session:
            self.log.error("Invalid session state for waiting page")
            self.redirect(url_path_join(self.base_url, 'hub', 'login'))
            return

        # Render waiting page
        html = self._render_custom_template(
            'duo_waiting.html',
            state=state,
            status_msg='Waiting for approval...'
        )
        self.finish(html)


class DuoAuthStatusHandler(BaseHandler):
    """Handler for polling Duo auth status during async push."""

    async def get(self):
        """Poll auth status and return JSON result."""
        state = self.get_argument('state', default=None)

        if not state:
            self.set_status(400)
            self.write({'error': 'Missing state parameter'})
            self.finish()
            return

        session = self.authenticator._auth_sessions.get(state)
        if not session:
            self.set_status(400)
            self.write({'error': 'Invalid or expired session'})
            self.finish()
            return

        txid = session.get('txid')
        if not txid:
            self.set_status(400)
            self.write({'error': 'No transaction in progress'})
            self.finish()
            return

        try:
            import duo_client

            auth_client = duo_client.Auth(
                ikey=self.authenticator.auth_api_ikey,
                skey=self.authenticator.auth_api_skey,
                host=self.authenticator.apihost
            )

            # Poll auth status
            status_result = auth_client.auth_status(txid)

            self.log.debug("Duo auth_status result: %s", status_result)

            result = status_result.get('result')

            if result == 'allow':
                # Authentication successful
                self.log.info("Duo async auth succeeded for user '%s'", session['duo_username'])

                # Clean up session
                self.authenticator._auth_sessions.pop(state, None)

                # Return success with redirect URL
                self.write({
                    'complete': True,
                    'success': True,
                    'redirect': self.get_next_url(session['user'].get('name', ''))
                })

            elif result == 'deny':
                # Authentication denied
                self.log.warning("Duo async auth denied: %s",
                    status_result.get('status_msg', 'No reason given'))

                # Clean up session
                self.authenticator._auth_sessions.pop(state, None)

                self.write({
                    'complete': True,
                    'success': False,
                    'error': status_result.get('status_msg', 'Authentication denied')
                })

            else:
                # Still waiting
                self.write({
                    'complete': False,
                    'status_msg': status_result.get('status', 'Waiting...')
                })

        except Exception as e:
            self.log.error("Duo auth_status failed: %s", str(e))
            self.set_status(500)
            self.write({'error': 'Failed to check authentication status'})

        self.finish()


class DuoAuthenticator(Authenticator):
    """Duo Two-Factor Authenticator using Duo Universal"""

    client_id = Unicode(
        help="""
        The Duo Client ID (formerly Integration Key).

        """
    ).tag(config=True)

    client_secret = Unicode(
        help="""
        The Duo Client Secret (formerly Secret Key).

        """
    ).tag(config=True)

    apihost =  Unicode(
        help="""
        The Duo API hostname.

        """
    ).tag(config=True)

    redirect_uri = Unicode(
        help="""
        The redirect URI for Duo Universal authentication.
        This should be the full URL to the Duo callback handler.
        Example: https://example.com/hub/duo-callback

        """
    ).tag(config=True)

    duo_mode = Unicode(
        'universal',
        help="""
        Duo authentication mode: 'universal' or 'auth_api'.

        'universal' uses Duo Universal Prompt (requires client_id/client_secret).
        'auth_api' uses Duo Auth API for legacy ikey/skey credentials.

        """
    ).tag(config=True)

    duo_default_bypass = Bool(
        False,
        help="""
        Default bypass behavior for users not in the DUO_USER_LIST.

        If True, users not found in the user mapping file will bypass Duo
        authentication and only need primary auth.
        If False (default), users not in the list will require Duo authentication.

        Can also be set via the DUO_DEFAULT_BYPASS environment variable.
        Set to '1', 'true', or 'yes' to enable bypass for unknown users.

        """
    ).tag(config=True)

    @default('duo_default_bypass')
    def _default_duo_default_bypass(self):
        """Get default bypass from environment variable."""
        env_val = os.environ.get('DUO_DEFAULT_BYPASS', '').lower()
        return env_val in ('1', 'true', 'yes')

    duo_user_list_path = Unicode(
        help="""
        Path to the CSV file containing user-to-Duo username mappings.

        The CSV file should have the format:
        username,duo_username,bypass

        Where bypass is '1' to skip Duo for that user, or '0'/'No' otherwise.

        Can also be set via the DUO_USER_LIST environment variable.
        If not set, no user mapping will be loaded.

        """
    ).tag(config=True)

    @default('duo_user_list_path')
    def _default_duo_user_list_path(self):
        """Get user list path from environment variable."""
        return os.environ.get('DUO_USER_LIST', '')

    auth_api_ikey = Unicode(
        help="""
        Duo Integration Key for Auth API mode.

        Use this with auth_api_skey for legacy Duo credentials that
        are incompatible with Duo Universal Prompt.

        """
    ).tag(config=True)

    auth_api_skey = Unicode(
        help="""
        Duo Secret Key for Auth API mode.

        Use this with auth_api_ikey for legacy Duo credentials that
        are incompatible with Duo Universal Prompt.

        """
    ).tag(config=True)

    auth_api_timeout = Unicode(
        '300',
        help="""
        Timeout in seconds for Auth API sessions.

        Defaults to 300 seconds (5 minutes).

        """
    ).tag(config=True)

    primary_auth_class = Type(PAMAuthenticator, Authenticator,
        help="""Class to use for primary authentication of users.

        Must follow the same structure as a standard authenticator class.

        Defaults to PAMAuthenticator.
        """
    ).tag(config=True)

    primary_authenticator = Instance(Authenticator)

    @default('primary_authenticator')
    def _primary_auth_default(self):
        return self.primary_auth_class(parent=self, db=self.db)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_mapping = {}
        self._load_user_mapping()
        self._current_auth_username = None
        self._current_duo_username = None
        self._current_bypass = False
        self._current_user = None
        self._state_mapping = {}  # Maps state to username for callback validation
        self._auth_sessions = {}  # Maps state -> {duo_username, devices, user, timestamp} for Auth API mode

    def _load_user_mapping(self):
        """Load user mapping from duo_user_list_path CSV file."""
        user_list_path = self.duo_user_list_path
        if user_list_path:
            try:
                with open(user_list_path, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3:
                            username = row[0].strip('"').strip()
                            duo_username = row[1].strip('"').strip()
                            bypass = row[2].strip('"').strip()
                            self._user_mapping[username] = {
                                'duo_username': duo_username,
                                'bypass': bypass == '1'
                            }
                    self.log.info("Loaded user mapping from %s", user_list_path)
            except Exception as e:
                self.log.warning("Failed to load user mapping from %s: %s",
                    user_list_path, str(e))

    def _get_duo_info(self, username):
        """Get Duo username and bypass flag for a given username.

        Returns a dict with 'duo_username' and 'bypass' keys.
        If username not found, returns the original username and the default bypass value.
        """
        if username in self._user_mapping:
            return self._user_mapping[username]
        return {'duo_username': username, 'bypass': self.duo_default_bypass}

    duo_custom_html = Unicode(
        help="""
        Custom html to use for Duo authentication page.
        Note: This is no longer used with Duo Universal redirect flow.

        Defaults to an empty string.
        """
    ).tag(config=True)

    def template_paths(self):
        """Return the path to the custom templates directory."""
        # Find where the package is installed
        import duoauthenticator
        pkg_dir = os.path.dirname(duoauthenticator.__file__)
        # Templates are installed in share/jupyterhub/templates relative to site-packages
        # or bundled with the package
        template_dir = os.path.join(os.path.dirname(pkg_dir), 'share', 'jupyterhub', 'templates')

        # Also check common installation locations
        possible_paths = [
            template_dir,
            os.path.join(sys.prefix, 'share', 'jupyterhub', 'templates'),
            '/usr/local/share/jupyterhub/templates',
            '/usr/share/jupyterhub/templates',
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return [path]

        return []

    def get_handlers(self, app):
        self.log.info("DuoAuthenticator get_handlers called - duo_mode: %s", self.duo_mode)
        if self.duo_mode == 'universal':
            return [
                (r'/login', DuoHandler),
                (r'/duo-callback', DuoCallbackHandler)
            ]
        else:  # auth_api mode
            return [
                (r'/login', DuoAuthAPIHandler),
                (r'/duo-auth', DuoAuthAPIHandler),
                (r'/duo-waiting', DuoWaitingHandler),
                (r'/duo-status', DuoAuthStatusHandler)
            ]

    async def authenticate(self, handler, data):
        """This method is no longer used with Duo Universal redirect flow.
        Authentication is handled through the DuoHandler and DuoCallbackHandler.
        """
        # This method is kept for backward compatibility but not used
        # in the Duo Universal flow
        return None

    async def do_primary_auth(self, handler, data):
        """Do primary authentication, and return the duo_username if successful.

        Return None otherwise.
        """
        user = await self.primary_authenticator.get_authenticated_user(handler, data)
        if user:
            username = user['name']
            # Get Duo info for this user
            duo_info = self._get_duo_info(username)
            self._current_auth_username = username
            self._current_duo_username = duo_info['duo_username']
            self._current_bypass = duo_info['bypass']
            self._current_user = user  # Store the full user dict for bypass scenario
            return self._current_duo_username
        else:
            return None