from jupyterhub.auth import Authenticator, PAMAuthenticator
from jupyterhub.handlers import LoginHandler, BaseHandler
from tornado import gen, web
from traitlets import Unicode, Type, Instance, default
import duo_universal
import csv
import os
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
                        username=None,
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
                        username=None,
                    )
                    self.finish(html)
        else:
            # self._render is defined by LoginHandler
            html = await self._render(
                login_error='Invalid username or password',
                username=None,
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
                username=None,
            )
            self.finish(html)
            return

        # Validate state
        if state not in self.authenticator._state_mapping:
            self.log.error("Invalid OAuth state received from Duo")
            html = await self._render(
                login_error='Authentication failed: invalid state',
                username=None,
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
                username=None,
            )
            self.finish(html)

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

    def _load_user_mapping(self):
        """Load user mapping from DUO_USER_LIST CSV file."""
        user_list_path = os.environ.get('DUO_USER_LIST')
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
        If username not found, returns the original username and bypass=False.
        """
        if username in self._user_mapping:
            return self._user_mapping[username]
        return {'duo_username': username, 'bypass': False}

    duo_custom_html = Unicode(
        help="""
        Custom html to use for Duo authentication page.
        Note: This is no longer used with Duo Universal redirect flow.

        Defaults to an empty string.
        """
    ).tag(config=True)

    def get_handlers(self,app):
        return [
            (r'/login', DuoHandler),
            (r'/duo-callback', DuoCallbackHandler)
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