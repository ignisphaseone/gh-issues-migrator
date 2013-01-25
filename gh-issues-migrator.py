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
gh_password = "example"
gh_token = None
source_repo = "test2"
target_repo = "test3"

# === GH API Config
gh_server = "https://api.github.com"


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
            print "Loading GitHub OAuth2 Token..."
            self.token = gh_token
        elif gh_username is not None and gh_password is not None:
            print "Loading GitHub Username and Password..."
            self.username = gh_username
            self.password = gh_password
        else:
            print "Loading from Config File..."
            try:
                config = ConfigParser()
                config.readfp(open('auth.config'))
                print config.items("github")
                section_name = "github"
                try:
                    self.token = config.get(section_name, "token")
                except Exception:
                    try:
                        self.username = config.get(section_name, "username")
                        self.password = config.get(section_name, "password")
                    except Exception:
                        raise InvalidAuthError("Cannot authenticate properly; no token, or no username/password")
            except Exception:
                pass

        if self.token is None and (self.username is None or self.password is None):
            print self.token, self.username, self.password
            raise InvalidAuthError("Cannot authenticate properly; no token, or no username/password")

    def auth_req(self, req):
        # Check if you have a token, and add it to the existing data in the URL.
        if self.token is not None:
            # If it's already got data, make sure it doesn't already have access_token and token_type keys.
            if req.has_data() and not ("access_token" in req.get_data() or "token_type" in req.get_data()):
                    rdata = json.loads(req.get_data())
                    rdata["access_token"] = self.token
                    rdata["token_type"] = "bearer"
            else:
                rdata = {}
                rdata["access_token"] = self.token
                rdata["token_type"] = "bearer"
            req.add_data(json.dumps(rdata, indent=2, sort_keys=True))

        #If you don't have a token, add basic authorization.
        else:
            req.add_header("Authorization", "Basic " + base64.urlsafe_b64encode(
                           "%s:%s" % (self.username, self.password)))

    def get_auths(self):
        #Check all the requirements for the API and see if you have proper
        #  authorizations required for github issue migration.
        #  This does not work if you are using token authorization though...
        req = new_req("%s/authorizations" % gh_server)
        self.auth_req(req)
        res = urllib2.urlopen(req)
        data = json.load(res)[0]
        return data["scopes"]

# === Globals
auth = Auth()


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
def new_req(url):
    res = urllib2.Request(url)
    res.add_header("Content-Type", "application/json")
    res.add_header("Accept", "application/json")
    return res


def get_src_milestones():
    req = new_req("%s/repos/%s/%s/milestones" % (gh_server, gh_username, source_repo))
    print "%s/repos/%s/%s/milestones" % (gh_server, gh_username, source_repo)
    auth.auth_req(req)
    res = urllib2.urlopen(req)
    data = json.load(res)
    print json.dumps(data, indent=4, sort_keys=True)
    return data


def get_src_labels():
    req = new_req("%s/repos/%s/%s/labels" % (gh_server, gh_username, source_repo))
    print "%s/repos/%s/%s/labels" % (gh_server, gh_username, source_repo)
    auth.auth_req(req)
    res = urllib2.urlopen(req)
    data = json.load(res)
    print json.dumps(data, indent=4, sort_keys=True)
    return data


def get_src_issues():
    req = new_req("%s/repos/%s/%s/issues" % (gh_server, gh_username, source_repo))
    print "%s/repos/%s/%s/issues" % (gh_server, gh_username, source_repo)
    auth.auth_req(req)
    res = urllib2.urlopen(req)
    data = json.load(res)
    print json.dumps(data, indent=4, sort_keys=True)
    return data


def get_tar_milestones():
    req = new_req("%s/repos/%s/%s/milestones" % (gh_server, gh_username, target_repo))
    print "%s/repos/%s/%s/milestones" % (gh_server, gh_username, target_repo)
    auth.auth_req(req)
    res = urllib2.urlopen(req)
    data = json.load(res)
    print json.dumps(data, indent=4, sort_keys=True)
    return data


def get_tar_labels():
    req = new_req("%s/repos/%s/%s/labels" % (gh_server, gh_username, target_repo))
    print "%s/repos/%s/%s/labels" % (gh_server, gh_username, target_repo)
    auth.auth_req(req)
    res = urllib2.urlopen(req)
    data = json.load(res)
    print json.dumps(data, indent=4, sort_keys=True)
    return data


def get_tar_issues():
    req = new_req("%s/repos/%s/%s/issues" % (gh_server, gh_username, target_repo))
    print "%s/repos/%s/%s/issues" % (gh_server, gh_username, target_repo)
    auth.auth_req(req)
    res = urllib2.urlopen(req)
    data = json.load(res)
    print json.dumps(data, indent=4, sort_keys=True)
    return data

# === Main
def main():
    src_milestones = get_src_milestones()
    src_labels = get_src_labels()
    src_issues = get_src_issues()
    tar_milestones = get_tar_milestones()
    tar_labels = get_tar_labels()
    tar_issues = get_tar_issues()
    print "Game Over!"

if __name__ == '__main__':
    main()
