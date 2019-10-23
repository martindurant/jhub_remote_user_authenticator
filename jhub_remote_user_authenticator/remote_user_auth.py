
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
import base64
import re
from tornado import gen, web
from traitlets import Unicode
ex = re.compile('''\"username\":\"(.*?)\"''')


class RemoteUserLoginHandler(BaseHandler):

    def get(self):
        print("in auth handler")
        data = self.request.headers.get("X-Amzn-Oidc-Data", "")
        if data == "":
            raise web.HTTPError(401)
        json = base64.b64decode(data).decode()
        user = ex.findall(json)
        print("got user", user)
        if not user:
            raise web.HTTPError(401)
        user = user[0]

        self.set_login_cookie(user)
        next_url = self.get_next_url(user)
        self.redirect(next_url)


class RemoteUserAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    """
    header_name = Unicode(
        default_value='REMOTE_USER',
        config=True,
        help="""HTTP header to inspect for the authenticated username.""")

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
