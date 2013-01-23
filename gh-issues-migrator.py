#!/usr/bin/python
"""
    gh-issues-migrator.py
    Eric Fong
    January 22, 2013

    Handles GitHub issue migration, using the GitHub v3 API. This includes
    importing all your milestones, issues, labels, and comments.

    This handles public and private repositories, and does its best to copy all
    issues and attributes as they exist in the previous repository.

    Changelog:
    v0.1
    --Initial Version.
"""
# === Imports
import urllib2
try:
    import simplejson as json
except ImportError:
    import json
from StringIO import StringIO
import base64
import ConfigParser

# === User Config
gh_username = "ignisphaseone"
gh_password = None
gh_token = None

# === GH API Config

# === GH Source/Target Config

# === Classes
class Auth:
    '''
        Container for authentication credentials.

        A container class which holds the authentication credentials for a user,
        instead of using the variables and modifying them directly.
    '''
    def __init__(self):
        '''
            Load credentials for use.

            Fetches your credentials, either from the config file, or from the
            program's local variables.
        '''
        self.token = None
        self.username = None
        self.password = None
        #Check script's variables.
        #--If you're given a token, use that.
        #--If you're given a username and a password, use those.
        #--If you're not given any valid combination of configs in program, check
        #  the config parser for token, then username/password combo.
        #--If you can't proceed, print an error and exit.

        if gh_token is not None:
            self.token = gh_token
        elif gh_username is not None and gh_password is not None:
            self.username = gh_username
            self.password = gh_password
        else:
            try:
                config = ConfigParser
                #config parser stuff
                pass
            except Exception:
                pass

        if self.token is None and (self.username is None or self.password is None):
            raise InvalidAuthError("Cannot authenticate properly; no token, or no username/password")

        #Check all the requirements for the API and see if you have proper
        #  authorizations required for github issue migration.
        pass #/__init__

    def auth_req(self, req):
        # Check if you have a token, and add it to the existing data in the URL.
        if self.token is not None and req.has_data():
            rdata = json.loads(req.get_data())
            if not (rdata.has_key("access_token") or rdata.has_key("token_type")):
                rdata = json.loads(req.get_data())
                rdata["access_token"] = self.token
                rdata["token_type"] = "bearer"
            req.add_data(json.dumps(rdata, indent=4, sort_keys=True))

        #If you don't have a token, add basic authorization.
        else:
            req.add_header("Authorization", "Basic " + base64.urlsafe_b64encode(
                           "%s:%s" % (self.username, self.password)))
        pass #/auth_req

    def post_auth_for_token(self):
        pass #/post_auth_for_token

    def get_auths(self):
        pass #/get_auths

class InvalidAuthError(Exception):
    '''
        Unable to create a valid Auth error.

        This error indicates that your credentials are not working properly,
        either because you do not have a token, or you do not have a username
        and password.
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class CannotMigrateError(Exception):
    '''
        Cannot migrate issues.

        This error indicates that you cannot migrate your issues for the
        specified reason, mainly because you have not generated an OAuth2 token
        for managing your repo's issues.
    '''
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

# === Functions

# === Main
def main():
    auth = Auth()
    print "Game Over!"
    pass #/main

if __name__ == '__main__':
    main()
