# Flask-ActiveDirectory

This is a one-file Flask boilerplate ready to use with Active Directory as authentication backend.

- By default, users can authenticate using their "sAMAccountName" as username

- Once authenticated, the session is updated with some attributes:

    - dn --> "distinguishedName" attribute

    - username --> "sAMAccountName" attribute

    - fullname --> "displayName" attribute

    - email --> "mail" attribute

    - roles --> list of roles for this user (see below)


## Configuration

Just add environment variables

```shell
# your application name
FLASK_APP="app"

# set to 'development' or 'production'
FLASK_ENV="development"

# define LDAP credentials
# Note: the application defaults to LDAPS without TLS certificate verification
LDAP_HOST="dc.company.com"
LDAP_USERNAME="CN=ldap_user,DC=company,DC=com"
LDAP_PASSWORD="Secret"
LDAP_BASE_DN="DC=company,DC=com"

# use a JSON formatted string to map roles with AD groups
# you can map multiple groups per role
# Note: a user can match multiple roles
LDAP_ROLES={"admin": ["CN=admin_users"], "read-only": ["CN=read_users"]}
```


## Basic Usage

During app development, simply start your app from the app directory

```shell
cd app
flask run --reload

```


The following routes are available:

- /login --> a basic form to authenticate, then redirects to /home
- /logout --> calling this URL clears the sessions and redirects to /login
- /home --> only available for authenticated users



User data is available in session object, along with user roles.
The simplest form of permissions checking can be something like:

```python
if "admin" in session.get("roles"):
    ...
elif "read-only" in session.get("roles"):
    ...
else:
    ...

```

