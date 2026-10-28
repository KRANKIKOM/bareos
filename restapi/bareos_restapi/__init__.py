#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# BAREOS - Backup Archiving REcovery Open Sourced
#
# Copyright (C) 2020-2023 Bareos GmbH & Co. KG
#
# This program is Free Software; you can redistribute it and/or
# modify it under the terms of version three of the GNU Affero General Public
# License as published by the Free Software Foundation, which is
# listed in the file LICENSE.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# Author: Maik Aussendorf
#

import configparser
import hashlib
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, status, Response, Path, Body, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import os
from packaging import version
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
import yaml

import threading

import bareos.bsock
import bareos.exceptions
import bareos.util
from bareos_restapi.models import *

# Read config from api.ini
config = configparser.ConfigParser()
config.read("api.ini")

CONFIG_DIRECTOR_ADDRESS = config.get("Director", "Address")
CONFIG_DIRECTOR_NAME = config.get("Director", "Name")
CONFIG_DIRECTOR_PORT = config.getint("Director", "Port")
# Directory the director loads resource files from (the `@` include tree that
# `configure add` and the Ansible bareos_fd role both write into). Required for
# modify/delete of clients, since bconsole has no `configure modify|delete` —
# we edit the resource file on disk and `reload`. The restapi runs co-located
# with the director, so it has filesystem access to this path.
CONFIG_DIRECTOR_RESOURCE_DIR = config.get(
    "Director", "ResourceDir", fallback="/etc/bareos/bareos-dir.d"
)
# Shared cluster secret the Ansible roles derive every inter-daemon password
# from (bareos_common_cluster_secret). With it set, a client created through
# the API gets the SAME password the FD side would get from Ansible (or can be
# told via /configuration/clients/{name}/fd-config): sha256(secret+host+"fd").
# Empty = no derivation; POST /configuration/clients then requires a password.
CONFIG_CLUSTER_SECRET = config.get("Director", "ClusterSecret", fallback="")
# Consoles allowed to use operations that touch resource files or FD secrets
# directly (client/job modify+delete, fd-config, password derivation). Those
# bypass the director's per-console ACLs, so they are restricted to explicitly
# trusted consoles (comma-separated names). Empty = nobody.
CONFIG_ADMIN_CONSOLES = {
    c.strip()
    for c in config.get("Director", "AdminConsoles", fallback="").split(",")
    if c.strip()
}

SECRET_KEY = config.get("JWT", "secret_key")
ALGORITHM = config.get("JWT", "algorithm")
ACCESS_TOKEN_EXPIRE_MINUTES = config.getint("JWT", "access_token_expire_minutes")

userDirectors = {}
users_db = {}

# Load metatags.yaml from the same directory.
with open(
    os.path.dirname(os.path.realpath(__file__)) + "/metatags.yaml", "r"
) as stream:
    tags_metadata = yaml.safe_load(stream)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(
    title="Bareos REST API",
    description="Bareos REST API built on python-bareos. Experimental and subject to enhancements and changes. **Note** swagger does not support GET methods with bodies, however, the CURL statements displayed by swagger do work.",
    version="0.0.1",
    openapi_tags=tags_metadata,
)


# Read-only console commands: safe to repeat after a reconnect. Anything else
# (run, configure add, delete, label, …) may already have reached the director
# before the socket died, so it is never replayed — the caller gets the error
# and the next request runs on a fresh connection.
_READONLY_COMMANDS = (
    "list", "llist", "show", "status", "version", ".api", ".bvfs_", ".jobs",
    ".clients", ".filesets", ".pools", ".storages", ".schedule", ".defaults",
)


class DirectorSession(object):
    """
    One director console connection per API user, shared by every request of
    that user. FastAPI runs (sync) endpoints concurrently in a threadpool, and
    several clients may use the same login (e.g. a web app and its worker):
    unserialized calls interleave on the socket, the reads get out of step and
    python-bareos reports "Assuming the connection is lost". A dead socket (e.g.
    after a director restart) was also never rebuilt — every call failed until
    the next /token.

    So: serialize calls per user, and on a connection error reconnect; replay
    the command once only if it is read-only.
    """

    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._lock = threading.Lock()
        self._conn = None
        self._connect()

    def _connect(self):
        self._conn = bareos.bsock.DirectorConsoleJson(
            address=CONFIG_DIRECTOR_ADDRESS,
            port=CONFIG_DIRECTOR_PORT,
            dirname=CONFIG_DIRECTOR_NAME,
            name=self._username,
            password=bareos.bsock.Password(self._password),
        )

    def _close(self):
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    @staticmethod
    def _connection_error(e):
        # Command errors come back as JsonRpc*; everything else from bsock (and
        # plain socket errors) means the transport is gone.
        if isinstance(e, bareos.exceptions.JsonRpcErrorReceivedException):
            return False
        return isinstance(e, (bareos.exceptions.Error, OSError))

    def call(self, command):
        with self._lock:
            if self._conn is None:
                self._connect()
            try:
                return self._conn.call(command)
            except Exception as e:
                if not self._connection_error(e):
                    raise
                self._close()
                self._connect()
                if str(command).lstrip().startswith(_READONLY_COMMANDS):
                    return self._conn.call(command)
                raise


class UserObject(object):
    def __init__(self, username, password):
        # self.id = id
        self.username = username
        self.password = password
        self.directorName = CONFIG_DIRECTOR_NAME
        self.director = bareos.bsock.BSock
        self.jsonDirector = bareos.bsock.DirectorConsoleJson
        self.directorVersion = ""  # Format: xx.yy.zz, example: 19.02.06

    def __str__(self):
        return "User(username='%s')" % (self.username)

    def __iter__(self):
        yield "username", self.username
        yield "directorName", self.directorName
        yield "directorVersion", self.directorVersion

    def getDirectorVersion(self):
        return self.directorVersion


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    if username in users_db:
        # print(users_db[username])
        # return {'username':username, 'directorName': users_db[username].directorName}
        return users_db[username]


def authenticate_user(username: str, password: str):
    # Re-login with the same credentials keeps the existing session: replacing
    # it would orphan a socket other in-flight requests are still using.
    existing = users_db.get(username)
    if (
        existing is not None
        and existing.password == password
        and isinstance(existing.jsonDirector, DirectorSession)
    ):
        return existing
    jsonDirector = None
    try:
        jsonDirector = DirectorSession(username, password)
    except Exception as e:
        print(
            "Could not authorize %s at director %s. %s"
            % (username, CONFIG_DIRECTOR_NAME, e)
        )
        return False
    user = UserObject(username, password)
    user.jsonDirector = jsonDirector
    user.username = username
    users_db[username] = user
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


## Generic Methods


def versionCheck(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    minVersion: Optional[str] = "16.1.1",
):
    myVersion = ""
    if current_user.directorVersion > "":
        myVersion = current_user.directorVersion
    else:
        result = read_director_version(response=response, current_user=current_user)
        if "version" in result:
            myVersion = bareos.util.Version(result["version"]).as_python_version()
            current_user.directorVersion = myVersion
        else:
            raise HTTPException(
                status_code=500,
                detail="Could not read version from director. Need at least version %s"
                % (minVersion),
            )
    try:
        if not (version.parse(myVersion) >= version.parse(minVersion)):
            raise HTTPException(
                status_code=501,
                detail="Not implemented in Bareos %s. Need at least version %s"
                % (myVersion, minVersion),
            )
        else:
            return True
    except version.InvalidVersion as exception:
        raise HTTPException(status_code=500, detail=str(exception))


def configure_add_standard_component(
    *,
    componentDef: BaseModel,
    response: Response,
    current_user: User = Depends(get_current_user),
    componentType=str,
):
    """
    Create a new Bareos standard component resource.
    Console command used: _configure add component_

    """

    addCommand = "configure add %s" % componentType
    componentDict = componentDef.dict()

    for a in componentDict:
        if componentDict[a] is not None:
            addCommand += " %s=%s" % (
                a,
                str(componentDict[a]).strip("[]").replace("'", "").replace(" ", ""),
            )
    # print(addCommand)
    # print(current_user)
    try:
        result = current_user.jsonDirector.call(addCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not add %s with command '%s'. Message: '%s'"
            % (componentType, addCommand, e)
        }

    if "configure" in result and "add" in result["configure"]:
        return result
    else:
        response.status_code = 500
        return {
            "message": "Could not add %s with command '%s' on director %s. Message: '%s'"
            % (componentType, addCommand, current_user.directorName, e)
        }


def switch_resource(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    resourceName: str,
    componentType=str,
    enable=bool,
):
    """
    Enables or disables a client, job or schedule
    Returns tuple: success(bool), json-return-string(dict)
    """
    responseDict = {}
    if enable:
        command = "enable "
    else:
        command = "disable "
    command += "%s=%s" % (componentType, resourceName)
    # print(command)
    try:
        responseDict = current_user.jsonDirector.call(command)
    except Exception as e:
        response.status_code = 500
        return (
            False,
            {
                "message": "Could not en/disable %s %s on director %s. Message: '%s'"
                % (componentType, resourceName, CONFIG_DIRECTOR_NAME, e)
            },
        )
    response.status_code = 200
    return (True, responseDict)


def parseCommandOptions(queryDict):
    optionString = ""
    for q in queryDict:
        if queryDict[q] is not None:
            if type(queryDict[q]) != bareosFlag:
                optionString += " %s=%s" % (q, str(queryDict[q]))
            else:
                if queryDict[q]:
                    optionString += " %s" % q
    return optionString


def show_configuration_items(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    itemType: str,
    byName: Optional[str] = None,
    verbose: Optional[bareosBool] = "yes",
):
    """
    Uses _show_ command to provide configuration setting
    """
    versionCheck(
        response=response,
        current_user=current_user,
        minVersion="20.0.1",
    )
    # Sometimes config type identificator differs from key returned by director, we need to map
    itemKey = itemType
    # itemTypeKeyMap = {"clients":"client", "jobs":"job", "pools":"pool", "schedules": "schedule", "storages":"storage", "users":"user", "profiles":"profile", "consoles":"console"}
    # if itemType in itemTypeKeyMap:
    #    itemKey = itemTypeKeyMap[itemType]

    foundItems = 0
    showCommand = "show %s" % itemType
    if byName:
        showCommand += "=%s" % byName
    if verbose:
        # print ("verbose on")
        showCommand += " verbose"
    try:
        responseDict = current_user.jsonDirector.call(showCommand)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Could not read %s from director %s. Message: '%s'"
            % (itemType, CONFIG_DIRECTOR_NAME, e),
        )
    # print(responseDict)
    if itemKey in responseDict:
        foundItems = len(responseDict[itemKey])
    if foundItems > 0 and byName:
        return responseDict[itemKey]
    elif foundItems > 0:
        return {"totalItems": foundItems, itemType: responseDict[itemKey]}
    else:
        raise HTTPException(status_code=404, detail="No %s found." % itemKey)


def list_catalog_items(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    itemType: str,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    jobQuery: Optional[jobQuery] = None,
    verbose: Optional[bareosBool] = "yes",
    hasCountOption: Optional[bareosBool] = "no",
):
    itemKey = itemType
    itemTypeKeyMap = {"files": "filenames"}
    if itemType in itemTypeKeyMap:
        itemKey = itemTypeKeyMap[itemType]
    if verbose:
        listCommand = "llist "
    else:
        listCommand = "list "
    listCommand += itemType
    queryDict = {}
    countDict = {}
    results = {}
    countCommand = listCommand
    if jobQuery is not None:
        queryDict = jobQuery.dict()
    for q in queryDict:
        if queryDict[q] is not None:
            listCommand += " %s=%s" % (q, str(queryDict[q]))
            countCommand += " %s=%s" % (q, str(queryDict[q]))
    if limit is not None:
        listCommand += " limit=%d" % limit
    if offset is not None:
        listCommand += " offset=%d" % offset
    countCommand += " count"
    try:
        responseDict = current_user.jsonDirector.call(listCommand)
        if hasCountOption:
            countDict = current_user.jsonDirector.call(countCommand)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Could not read %s list from director %s. Message: '%s'"
                % (itemType, CONFIG_DIRECTOR_NAME, e)
            },
        )
    foundItems = len(responseDict)
    if (
        hasCountOption == "yes"
        and itemKey in countDict
        and "count" in countDict[itemKey][0]
    ):
        results["totalItems"] = countDict[itemKey][0]["count"]
    else:
        results["totalItems"] = foundItems
    if foundItems > 0:
        # check for limit / offset
        if limit is not None:
            results["limit"] = limit
        if offset is not None:
            results["offset"] = offset
        return {**results, itemKey: responseDict[itemKey]}
    else:
        raise HTTPException(
            status_code=404, detail={"message": "No %s found." % itemType}
        )


### Clients ###
@app.get("/control/clients", status_code=200, tags=["clients", "control"])
def read_catalog_info_for_all_clients(
    response: Response,
    current_user: User = Depends(get_current_user),
    name: Optional[str] = None,
):
    """
    Read status information from catalog about all clients or just one client by name.
    Built on console command _llist client_
    """
    if name:
        listCommand = "llist client=%s" % name
    else:
        listCommand = "llist clients"
    try:
        responseDict = current_user.jsonDirector.call(listCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read client list from director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    if "clients" in responseDict:
        totalItems = len(responseDict["clients"])
        return {"totalItems": totalItems, "clients": responseDict["clients"]}
    else:
        response.status_code = 404
        return {"message": "No clients found."}


@app.get("/control/clients/{client_id}", tags=["clients", "control"])
def read_catalog_info_for_particular_client(
    *,
    client_id: int = Path(..., title="The ID of client to get", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Read catalog information for one client by id.
    Built on console command _llist client_

    **Warning** Director does not support direct query by _id_ we query all clients and filter the result.
    Maybe more time consuming than expected in large settings.
    """
    allClients = read_catalog_info_for_all_clients(response, current_user)
    result = None
    for c in allClients["clients"]:
        if c["clientid"] == str(client_id):
            result = c
            break
    if result:
        return result
    else:
        response.status_code = 404
        return {
            "message": "Client with Client ID {client_id} not found".format(
                client_id=client_id
            )
        }
    return {"item_id": item_id}


@app.get("/control/clients/{client_name}/status", tags=["clients", "control"])
def client_health(
    *,
    client_name: str = Path(..., title="Client (name) to health-check"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Live health check for one client (FD).

    Runs `status client=<name>`, which makes the Director open a connection to
    the file daemon and authenticate. That single probe answers both questions
    a setup/overview view needs:
      - reachable: the FD is up and accepting connections (ping), and
      - the Director's credentials for it are accepted (login works).

    A failure to connect or authenticate is reported as `reachable: false` with
    the Director's message — it is NOT a 5xx, since "client is down" is a valid,
    expected answer to a health check.

    Uses a raw (non-JSON) console: the Director's JSON API does not serialize
    the `status client` subcommand (it returns `{}` for up and down alike), so
    the JSON console can't tell them apart. The raw text carries the FD's
    version/uptime banner on success and a connect/auth error on failure.
    """
    try:
        name = _validate_resource(client_name, "client name")
    except ValueError as e:
        response.status_code = 400
        return {"detail": str(e)}

    raw_console = None
    try:
        raw_console = bareos.bsock.DirectorConsole(
            address=CONFIG_DIRECTOR_ADDRESS,
            port=CONFIG_DIRECTOR_PORT,
            dirname=CONFIG_DIRECTOR_NAME,
            name=current_user.username,
            password=bareos.bsock.Password(current_user.password),
        )
        result = raw_console.call("status client=%s" % name)
    except Exception as e:
        return {"name": name, "reachable": False, "message": str(e)}
    finally:
        if raw_console is not None:
            try:
                raw_console.close()
            except Exception:
                pass

    text = result.decode("utf-8", "replace") if isinstance(result, bytes) else str(result)
    low = text.lower()
    failure_markers = (
        "failed to connect",
        "bnet_connect",
        "cannot connect",
        "could not connect",
        "connection refused",
        "unable to authenticate",
        "authorization key rejected",
        "no such client",
    )
    success_markers = ("daemon started", "handshake:")
    if any(m in low for m in failure_markers):
        reachable = False
    elif any(m in low for m in success_markers) or ("%s version:" % name.lower()) in low:
        reachable = True
    else:
        reachable = False

    # Keep the reply small; the banner (version/OS/uptime) is the useful part.
    snippet = text.strip()
    if len(snippet) > 600:
        snippet = snippet[:600] + " …"
    return {"name": name, "reachable": reachable, "message": snippet}


@app.put(
    "/control/clients/enable/{client_name}",
    status_code=204,
    tags=["clients", "control"],
)
def enable_client(
    *,
    client_name: str = Path(..., title="The client (name) to enable"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    (result, jsonMessage) = switch_resource(
        response=response,
        current_user=current_user,
        resourceName=client_name,
        componentType="client",
        enable=True,
    )
    return jsonMessage


@app.put(
    "/control/clients/disable/{client_name}",
    status_code=204,
    tags=["clients", "control"],
)
def disable_client(
    *,
    client_name: str = Path(..., title="The client (name) to disable"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    (result, jsonMessage) = switch_resource(
        response=response,
        current_user=current_user,
        resourceName=client_name,
        componentType="client",
        enable=False,
    )
    return jsonMessage


@app.get("/configuration/clients", tags=["clients", "configuration"])
def read_all_clients(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show clients_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="clients",
        verbose=verbose,
    )


@app.get("/configuration/clients/{clients_name}", tags=["clients", "configuration"])
def read_client_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    clients_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show clients_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="clients",
        byName=clients_name,
        verbose=verbose,
    )


def _derivation_candidates(name, address=None):
    """
    Hostnames a client may derive its password from — bound to the client's
    own NAME only (the address can't steer it), so a caller can't use the
    endpoint as an oracle for arbitrary hosts: the name minus a trailing "-fd"
    (legacy convention, default) and the bare name (modern convention, where
    the client is named like its host). `address` is ignored on purpose.
    """
    out = []
    if name.lower().endswith("-fd"):
        out.append(name[:-3])
    out.append(name)
    return list(dict.fromkeys(out))


def _derivation_hostname(name, address, hostname=None):
    """
    Short hostname for password derivation — what Ansible calls
    ansible_hostname. An explicit `hostname` must be one of the client's own
    candidates (see _derivation_candidates); default is the first candidate.
    """
    candidates = _derivation_candidates(name, address)
    if hostname:
        h = hostname.strip()
        if h not in candidates:
            raise ValueError(
                "hostname must be one of %s (derived from the client's name/address)"
                % ", ".join(candidates)
            )
        return h
    return candidates[0]


def _derive_fd_password(hostname):
    """sha256(ClusterSecret + hostname + "fd") — identical to the bareos_fd role."""
    return hashlib.sha256(
        (CONFIG_CLUSTER_SECRET + hostname + "fd").encode("utf-8")
    ).hexdigest()


@app.post("/configuration/clients", tags=["clients", "configuration"])
def post_client(
    *,
    clientDef: clientCreate = Body(..., title="The client to create"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a client (`configure add client`). The director writes it to
    <ResourceDir>/client/<name>.conf, so it persists across restarts.

    Without a password it is derived from the cluster secret (see
    clientCreate). The plaintext is not returned here — fetch the FD-side
    block via GET /configuration/clients/{name}/fd-config.
    """
    data = clientDef.dict()
    hostname = data.pop("hostname", None)
    try:
        _validate_resource(str(data.get("name", "")), "client name")
        for key, value in data.items():
            if isinstance(value, str):
                _reject_control_chars(value, key)
    except ValueError as e:
        response.status_code = 400
        return {"message": str(e)}

    derived_from = None
    if not data.get("password"):
        if not CONFIG_CLUSTER_SECRET:
            response.status_code = 400
            return {
                "message": "password is required (no ClusterSecret configured "
                "for password derivation)"
            }
        # Deriving uses the cluster secret, which bypasses console ACLs.
        denied = _authorize_resource_op(current_user)
        if denied:
            response.status_code = 403
            return {"message": denied}
        try:
            derived_from = _derivation_hostname(data["name"], data.get("address"), hostname)
            _validate_resource(derived_from, "hostname")
        except ValueError as e:
            response.status_code = 400
            return {"message": str(e)}
        data["password"] = _derive_fd_password(derived_from)

    result = configure_add_standard_component(
        componentDef=clientResource(**data),
        response=response,
        current_user=current_user,
        componentType="client",
    )
    if derived_from and isinstance(result, dict) and (response.status_code or 200) < 400:
        result = dict(result)
        result["passwordDerivedFrom"] = derived_from
    return result


@app.get(
    "/configuration/clients/{clients_name}/fd-config",
    tags=["clients", "configuration"],
)
def read_client_fd_config(
    *,
    clients_name: str = Path(..., title="Client name"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    The `Director { … }` block the file daemon needs to accept this director —
    the half of onboarding the API can't do itself. For a legacy bacula-fd it
    is the extra block in bacula-fd.conf; when the client resource has TLS off
    (bacula-fd 5.2.6 can't do TLS-PSK) the snippet turns TLS off as well.

    The password comes from the client's resource file (stored in plaintext
    there; `show client` only exposes a hash).
    """
    try:
        name = _validate_resource(clients_name, "client name")
        path = _resource_file_path("client", name)
    except ValueError as e:
        response.status_code = 400
        return {"message": str(e)}
    denied = _authorize_resource_op(current_user, "client", name)
    if denied:
        response.status_code = 403
        return {"message": denied}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        response.status_code = 404
        return {"message": "No resource file for client %s at %s" % (name, path)}
    except OSError as e:
        response.status_code = 500
        return {"message": "Could not read %s: %s" % (path, e)}

    pw = re.search(r'^\s*Password\s*=\s*"?([^"\n]*?)"?\s*$', text, re.I | re.M)
    if not pw or not pw.group(1):
        response.status_code = 409
        return {"message": "No password found in %s" % path}
    password = pw.group(1)
    if password.startswith("[md5]"):
        response.status_code = 409
        return {"message": "Password in %s is hashed; plaintext not recoverable" % path}
    tls = re.search(r"^\s*TLS\s*Enable\s*=\s*(\w+)", text, re.I | re.M)
    tls_off = bool(tls) and tls.group(1).lower() in ("no", "false", "0")

    lines = [
        "Director {",
        "  Name = %s" % CONFIG_DIRECTOR_NAME,
        '  Password = "%s"' % password,
    ]
    if tls_off:
        lines += ["  TLS Enable = no", "  TLS Require = no"]
    lines.append("}")
    return {
        "name": name,
        "director": CONFIG_DIRECTOR_NAME,
        "tlsDisabled": tls_off,
        "config": "\n".join(lines) + "\n",
    }


# ---------- Client modify / delete (file-based) ----------
# bconsole's `configure` command only supports `add` and `export` (see
# core/src/dird/ua_configure.cc) — there is no `modify` or `delete`. Both
# `configure add` and the Ansible bareos_fd role write one resource file per
# client to <ResourceDir>/client/<name>.conf, so modify == rewrite that file
# and delete == remove it; a `reload` makes the director pick up the change.
# Validation reuses _validate_resource() (defined with the BVFS validators
# below): the resource-name charset [A-Za-z0-9._-]+ has no path separator, and
# _resource_file_path() additionally refuses any path that escapes ResourceDir.


def _resource_file_path(componentType, name):
    """
    Absolute path of a resource file: <ResourceDir>/<componentType>/<name>.conf.

    Defense in depth: the resolved path must stay directly inside
    <ResourceDir>/<componentType>, so a crafted name can never escape the
    directory even if the name charset check is ever loosened.
    """
    base = os.path.realpath(
        os.path.join(CONFIG_DIRECTOR_RESOURCE_DIR, componentType)
    )
    target = os.path.realpath(os.path.join(base, name + ".conf"))
    if os.path.dirname(target) != base:
        raise ValueError("resolved resource path escapes %s" % base)
    return target


def _reject_control_chars(value, label="value"):
    """
    Refuse control characters in anything that ends up in a resource file or a
    console command line: a newline would let a value inject extra directives
    or a second command.
    """
    s = str(value)
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in s):
        raise ValueError("%s must not contain control characters (newline, NUL, …)" % label)
    return s


def _quote_directive_string(value):
    s = _reject_control_chars(value)
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def _authorize_resource_op(current_user, componentType=None, name=None):
    """
    Gate for operations that read/write resource files or FD secrets directly
    and therefore bypass the director's console ACLs. The caller's console must
    be listed in [Director] AdminConsoles, and an existing resource must be
    visible through the caller's own console (`show` is ACL-filtered).
    Returns an error message, or None when allowed.
    """
    if current_user.username not in CONFIG_ADMIN_CONSOLES:
        return (
            "console '%s' may not manage resource files or FD secrets "
            "(see [Director] AdminConsoles)" % current_user.username
        )
    if componentType and name:
        key = componentType + "s"
        try:
            shown = current_user.jsonDirector.call("show %s=%s" % (key, name))
        except Exception as e:
            return "could not verify access to %s '%s': %s" % (componentType, name, e)
        coll = shown.get(key) if isinstance(shown, dict) else None
        if not isinstance(coll, dict) or name not in coll:
            return "%s '%s' is not visible to console '%s'" % (
                componentType,
                name,
                current_user.username,
            )
    return None


def _format_directive_value(value):
    """Render one directive value for a Bareos resource file."""
    # bareosBool is a str-Enum, so test it before the generic str branch.
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, bareosBool):
        return value.value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return ", ".join(_quote_directive_string(v) for v in value)
    return _quote_directive_string(value)


# Client-resource directive aliases (from core/src/dird/dird_conf.cc,
# client_items[]). Normalizing these to the canonical name keeps a merge from
# emitting both the alias and the canonical directive: the Ansible bareos_fd
# role writes `FDPort`, our model uses `port` — the same underlying directive.
_CLIENT_ALIASES = {
    "fdport": "port",
    "fdaddress": "address",
    "fdpassword": "password",
}


# Jobs need no alias normalization — the bareos_config role's Job template and
# the jobResource model already agree on directive names (Client, FileSet,
# Pool, Schedule, JobDefs, RunBeforeJob, ...). Kept explicit for symmetry and
# so a future alias can be added without touching call sites.
_JOB_ALIASES = {}


def _norm_directive_key(key, aliases):
    """Canonical directive key: lowercased, whitespace-stripped, alias-resolved."""
    norm = re.sub(r"\s+", "", key).lower()
    return aliases.get(norm, norm)


def _parse_resource_directives(content, aliases):
    """
    Parse a flat resource block into an ordered list of (key, raw_value): keys
    canonicalized via _norm_directive_key, values kept verbatim (quotes and
    all). Adequate for the resources we manage (Client, Job) — they carry no
    nested sub-blocks in the files `configure add` / Ansible write.
    """
    directives = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("{") or stripped == "}":
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        directives.append((_norm_directive_key(key, aliases), value.strip()))
    return directives


def _merge_resource_block(resourceType, current, overrides, forced_name, aliases):
    """
    Merge `overrides` (canonical key -> already-formatted value) into the
    directives parsed from `current` and return (rendered_block, keys_present).

    Unspecified directives are preserved verbatim, so a partial modify never
    silently drops settings; `name` is forced (URL is authoritative) and
    emitted first. keys_present lets the caller assert required directives
    (e.g. a client password) survived the merge.
    """
    seen = set()
    lines = ["%s {" % resourceType]
    lines.append("  Name = %s" % forced_name)
    seen.add("name")
    for key, raw in _parse_resource_directives(current, aliases):
        if key in seen:
            continue
        seen.add(key)
        lines.append("  %s = %s" % (key, overrides.get(key, raw)))
    for key, val in overrides.items():
        if key in seen:
            continue
        seen.add(key)
        lines.append("  %s = %s" % (key, val))
    lines.append("}")
    return "\n".join(lines) + "\n", seen


def _write_resource_file(path, content):
    """Atomically write a resource file with director-readable permissions."""
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(content)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def _reload_after(current_user, response, path, rollback_content, action):
    """
    Reload the director after a resource-file change. On reload failure, restore
    rollback_content (or delete the file when None) so the on-disk config and
    the director's in-memory config never diverge. Returns the reload payload.
    """
    def rollback(reason):
        try:
            if rollback_content is None:
                if os.path.isfile(path):
                    os.remove(path)
            else:
                _write_resource_file(path, rollback_content)
        except OSError:
            pass
        response.status_code = 500
        return {
            "message": "%s but director reload failed (rolled back). Message: '%s'"
            % (action, reason)
        }

    try:
        result = current_user.jsonDirector.call("reload")
    except Exception as e:
        return rollback(e)
    payload = result.get("reload", result) if isinstance(result, dict) else result
    if isinstance(result, dict) and "error" in result:
        return rollback(result["error"])
    if isinstance(payload, dict) and str(payload.get("success", "")).lower() in (
        "false",
        "no",
        "0",
    ):
        return rollback(payload)
    return payload


def _modify_resource(
    *,
    response,
    current_user,
    componentType,
    resourceType,
    name_raw,
    data,
    aliases,
    required_keys=(),
):
    """
    Shared merge-modify for file-based resources (Client, Job). Merges the
    non-null fields of `data` into <ResourceDir>/<componentType>/<name>.conf and
    reloads. required_keys are directives that must be present after the merge
    (e.g. a client's password) — a friendly 400 beats a reload failure.
    """
    try:
        name = _validate_resource(name_raw, "%s name" % componentType)
        path = _resource_file_path(componentType, name)
    except ValueError as e:
        response.status_code = 400
        return {"detail": str(e)}

    if not os.path.isfile(path):
        response.status_code = 404
        return {
            "detail": "%s '%s' does not exist. Use POST to create it."
            % (resourceType, name)
        }

    denied = _authorize_resource_op(current_user, componentType, name)
    if denied:
        response.status_code = 403
        return {"detail": denied}

    body_name = data.get("name")
    if body_name is not None:
        try:
            if _validate_resource(str(body_name), "name") != name:
                raise ValueError("mismatch")
        except ValueError:
            response.status_code = 400
            return {
                "detail": "Body name '%s' does not match URL '%s'."
                % (body_name, name)
            }

    with open(path, "r") as fh:
        current = fh.read()

    overrides = {}
    try:
        for key, value in data.items():
            if key == "name" or value is None:
                continue
            overrides[_norm_directive_key(key, aliases)] = _format_directive_value(value)
    except ValueError as e:
        response.status_code = 400
        return {"detail": str(e)}

    block, keys_present = _merge_resource_block(
        resourceType, current, overrides, _format_directive_value(name), aliases
    )
    for req in required_keys:
        if req not in keys_present:
            response.status_code = 400
            return {
                "detail": "'%s' is required (not on disk or in the request)." % req
            }

    try:
        _write_resource_file(path, block)
    except OSError as e:
        response.status_code = 500
        return {"detail": "Could not write %s '%s': %s" % (componentType, name, e)}

    reload_result = _reload_after(
        current_user, response, path, current, "Updated %s '%s'" % (componentType, name)
    )
    if response.status_code is not None and response.status_code >= 400:
        return reload_result
    return {"message": "%s '%s' updated." % (resourceType, name), "reload": reload_result}


def _delete_resource(*, response, current_user, componentType, resourceType, name_raw):
    """
    Shared delete for file-based resources: remove
    <ResourceDir>/<componentType>/<name>.conf and reload. A reload failure
    (e.g. something still references the resource) rolls the file back.
    """
    try:
        name = _validate_resource(name_raw, "%s name" % componentType)
        path = _resource_file_path(componentType, name)
    except ValueError as e:
        response.status_code = 400
        return {"detail": str(e)}

    if not os.path.isfile(path):
        response.status_code = 404
        return {"detail": "No %s resource file for '%s'." % (componentType, name)}

    denied = _authorize_resource_op(current_user, componentType, name)
    if denied:
        response.status_code = 403
        return {"detail": denied}

    try:
        with open(path, "r") as fh:
            backup = fh.read()
        os.remove(path)
    except OSError as e:
        response.status_code = 500
        return {"detail": "Could not remove %s '%s': %s" % (componentType, name, e)}

    reload_result = _reload_after(
        current_user, response, path, backup, "Removed %s '%s'" % (componentType, name)
    )
    if response.status_code is not None and response.status_code >= 400:
        return reload_result
    return {"message": "%s '%s' deleted." % (resourceType, name), "reload": reload_result}


@app.put("/configuration/clients/{clients_name}", tags=["clients", "configuration"])
def put_client(
    *,
    clients_name: str = Path(..., title="Client (name) to modify"),
    clientDef: clientUpdate = Body(..., title="Desired client state"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Modify a client resource (partial, merge semantics).

    bconsole has no `configure modify`, so the fields you send are merged into
    the resource file at <ResourceDir>/client/<name>.conf and the director is
    reloaded. Directives you omit are preserved — in particular, omit
    `password` to keep the current FD secret (a `show` only exposes the hash,
    so the UI can't resend the plaintext). The client must already exist — use
    POST /configuration/clients to create. The URL {clients_name} is
    authoritative; a `name` in the body must match it (there is no rename).
    """
    return _modify_resource(
        response=response,
        current_user=current_user,
        componentType="client",
        resourceType="Client",
        name_raw=clients_name,
        data=clientDef.dict(),
        aliases=_CLIENT_ALIASES,
        required_keys=("password",),
    )


@app.delete(
    "/configuration/clients/{clients_name}", tags=["clients", "configuration"]
)
def delete_client(
    *,
    clients_name: str = Path(..., title="Client (name) to delete"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Delete a client resource from the director.

    bconsole has no `configure delete`, so the resource file at
    <ResourceDir>/client/<name>.conf is removed and the director reloaded.

    NOTE: if a Job or JobDefs still references this client the reload will
    report a configuration error and the delete is rolled back — remove or
    repoint those jobs first.
    """
    return _delete_resource(
        response=response,
        current_user=current_user,
        componentType="client",
        resourceType="Client",
        name_raw=clients_name,
    )


### catalogs


@app.get("/configuration/catalogs", tags=["catalogs", "configuration"])
def read_all_catalogs(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all catalog resources. Built on console command _show catalogs_.
    Used by the UI to populate the client's Catalog dropdown.
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="catalogs",
        verbose=verbose,
    )


### resource ownership (hybrid: Ansible baseline vs UI deltas)


def _scan_ansible_managed(componentType):
    """
    Map <name> -> bool for every <ResourceDir>/<componentType>/<name>.conf,
    where bool is whether the file carries the ANSIBLE-MANAGED marker (same
    convention the bareos_config reaper matches). Lets the UI lock editing of
    Ansible-owned resources so a UI change can't be silently reverted by the
    next Ansible run. A resource created via `configure add` that isn't on this
    node's disk simply won't appear (treated as unmanaged by the caller).
    """
    out = {}
    base = os.path.realpath(os.path.join(CONFIG_DIRECTOR_RESOURCE_DIR, componentType))
    if not os.path.isdir(base):
        return out
    for filename in os.listdir(base):
        if not filename.endswith(".conf"):
            continue
        name = filename[: -len(".conf")]
        try:
            with open(os.path.join(base, filename), "r") as fh:
                out[name] = "ANSIBLE-MANAGED" in fh.read()
        except OSError:
            continue
    return out


@app.get("/configuration/managed-resources", tags=["configuration"])
def managed_resources(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Report which client/job resource files are Ansible-managed (carry the
    ANSIBLE-MANAGED marker). Pure filesystem scan of the Director's resource
    dir — no console call. The UI uses this to badge + lock Ansible-owned
    resources under the hybrid ownership model.
    """
    return {"client": _scan_ansible_managed("client"), "job": _scan_ansible_managed("job")}


### filesets


@app.get("/configuration/filesets", tags=["filesets", "configuration"])
def read_all_filesets(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show filesets_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="filesets",
        verbose=verbose,
    )


@app.get("/configuration/filesets/{filesets_name}", tags=["filesets", "configuration"])
def read_fileset_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    filesets_name: str = Path(..., title="fileset name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show filesets_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="filesets",
        byName=filesets_name,
        verbose=verbose,
    )


#### Job Control


@app.post("/control/jobs/run", tags=["jobcontrol", "control", "jobs"])
def runJob(
    *,
    jobControl: jobControl = Body(..., title="Job control information", embed=True),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Run a job, defined by jobControl record.

    **Note**: Swagger throws a weird error when running this command by the UI,
    while the given curl statement works fine.
    """
    result = None
    jobCommand = "run"
    args = jobControl.dict()
    for a in args:
        if args[a] is not None:
            jobCommand += " %s=%s" % (a, str(args[a]))
    # print(jobCommand)
    try:
        result = current_user.jsonDirector.call(jobCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not start job '%s' on director %s. Message: '%s'"
            % (jobCommand, current_user.directorName, e)
        }
    if "run" in result and "jobid" in result["run"]:
        return {"jobid": int(result["run"]["jobid"])}
    else:
        response.status_code = 500
        return {"message": "Job '%s' triggered but no jobId returned" % jobCommand}


@app.post("/control/jobs/rerun/{job_id}", tags=["jobcontrol", "control", "jobs"])
def rerun_Job_by_jobid(
    *,
    job_id: int = Path(..., title="The ID of job to rerun", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Rerun a specific job given bei jobid
    """
    result = None
    rerunCommand = "rerun jobid=%d" % job_id
    try:
        result = current_user.jsonDirector.call(rerunCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not rerun jobid %d on director %s. Message: '%s'"
            % (job_id, current_user.directorName, e)
        }
    if "run" in result and "jobid" in result["run"]:
        return {"jobid": int(result["run"]["jobid"])}
    else:
        response.status_code = 500
        return {"message": "Job '%s' triggered but no jobId returned" % jobCommand}


@app.post("/control/jobs/rerun", tags=["jobcontrol", "control", "jobs"])
def rerun_Job(
    *,
    job_range: jobRange = Body(..., title="Job range to rerun"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Rerun jobs given by the following parameters (at least one)

    - **since_jobid**=_jobid_ rerun failed jobs since this jobid
    - **until_jobid**=_jobid_ - in conjunction with _since_jobid_
    - **days**=_nr_days_ - since a number of days
    - **hours**=_nr_hours_ - since a number of hours

    Built on console command _rerun_
    """
    result = None
    rerunCommand = "rerun"
    args = job_range.dict()
    for a in args:
        if args[a] is not None:
            rerunCommand += " %s=%s" % (a, args[a])
    rerunCommand += " yes"
    try:
        result = current_user.jsonDirector.call(rerunCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not %s on director %s. Message: '%s'"
            % (rerunCommand, current_user.directorName, e)
        }
    # print(result)
    if "run" in result and "jobid" in result["run"]:
        return {"jobid": int(result["run"]["jobid"])}
    else:
        response.status_code = 500
        return {"message": "Job '%s' triggered but no jobId returned" % rerunCommand}


@app.post("/control/jobs/restore", tags=["jobcontrol", "control", "jobs"])
def runRestoreJob(
    *,
    jobControl: restoreJobControl = Body(
        ..., title="Restore Job control information", embed=True
    ),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Run a restore-job, defined by jobControl record.

    """
    result = None
    jobCommand = "restore"
    args = jobControl.dict()
    for a in args:
        # print(" %s=%s" % (a, str(args[a])))
        if args[a] is not None:
            if a != "selectAllDone":
                jobCommand += " %s=%s" % (a, str(args[a]))
            elif args[a] == "yes":
                jobCommand += " select all done"
    # print(jobCommand)
    try:
        result = current_user.jsonDirector.call(jobCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not start job '%s' on director %s. Message: '%s'"
            % (jobCommand, current_user.directorName, e)
        }
    if "run" in result and "jobid" in result["run"]:
        return {"jobid": int(result["run"]["jobid"])}
    else:
        response.status_code = 500
        return {"message": "Job '%s' triggered but no jobId returned" % jobCommand}


@app.put("/control/jobs/cancel/{job_id}", tags=["jobcontrol", "control", "jobs"])
def cancelJob(
    *,
    job_id: int = Path(..., title="The ID of job to cancel", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Cancel a specific job given bei jobid
    """
    # cancel a specific job given bei jobid
    cancelCommand = "cancel jobid=%d" % job_id
    result = None
    try:
        result = current_user.jsonDirector.call(cancelCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not cancel jobid %d on director %s. Message: '%s'"
            % (job_id, current_user.directorName, e)
        }
    return result


@app.put(
    "/control/jobs/enable/{job_name}",
    status_code=204,
    tags=["jobcontrol", "jobs", "control"],
)
def enable_job(
    *,
    job_name: str = Path(..., title="The job (name) to enable"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    (result, jsonMessage) = switch_resource(
        response=response,
        current_user=current_user,
        resourceName=job_name,
        componentType="job",
        enable=True,
    )
    return jsonMessage


@app.put(
    "/control/jobs/disable/{job_name}",
    status_code=204,
    tags=["jobcontrol", "jobs", "control"],
)
def disable_job(
    *,
    job_name: str = Path(..., title="The job (name) to disable"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    (result, jsonMessage) = switch_resource(
        response=response,
        current_user=current_user,
        resourceName=job_name,
        componentType="job",
        enable=False,
    )
    return jsonMessage


#### Job Status


@app.get("/control/jobs/totals", tags=["jobcontrol", "control", "jobs"])
def read_all_jobs_totals(
    *, response: Response, current_user: User = Depends(get_current_user)
):
    listCommand = "llist jobtotals"
    results = {}
    try:
        responseDict = current_user.jsonDirector.call(listCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read job totals from director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    if "jobtotals" in responseDict:
        return responseDict
    else:
        response.status_code = 404
        return {"message": "No jobtotals found."}


@app.get("/control/jobs/{job_id}", tags=["jobcontrol", "control", "jobs"])
def read_job_status(
    *,
    job_id: int = Path(..., title="The ID of job to get", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Read information about a specific job defined by jobid
    Returns output of command _llist jobid=id_
    """
    result = None
    listCommand = "llist jobid=%d" % job_id
    try:
        result = current_user.jsonDirector.call(listCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not query jobs on director %s. Message: '%s'"
            % (current_user.directorName, e)
        }
    if result and "jobs" in result:
        return result["jobs"][0]
    else:
        response.status_code = 404
        return {"message": "Job with Job ID {jobid} not found".format(jobid=job_id)}


# Job states after which there is nothing live to show any more.
_TERMINAL_JOB_STATES = {"T", "W", "E", "e", "f", "A"}


@app.get("/control/jobs/{job_id}/live", tags=["jobcontrol", "control", "jobs"])
def read_job_live(
    *,
    job_id: int = Path(..., title="The ID of the job", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Live progress of a running job.

    The catalog only gets JobFiles/JobBytes when a job ends, so live numbers
    come from the file daemon: this runs `status client=<the job's client>` on
    a raw console (the JSON API doesn't serialize that subcommand) and returns
    the text. The caller parses the "JobId <id>" block (files, bytes, rate,
    current file) — same format as Bacula's, so existing parsers apply.
    For a finished job `running` is false and `status` is empty.
    """
    try:
        found = current_user.jsonDirector.call("llist jobid=%d" % job_id)
    except Exception as e:
        response.status_code = 500
        return {"message": "Could not query job %d: %s" % (job_id, e)}
    jobs = (found or {}).get("jobs") or []
    if not jobs:
        response.status_code = 404
        return {"message": "Job with Job ID %d not found" % job_id}
    info = jobs[0]
    jobstatus = str(info.get("jobstatus", ""))
    client = str(info.get("client", ""))
    base = {"jobid": job_id, "jobstatus": jobstatus, "client": client}
    if jobstatus in _TERMINAL_JOB_STATES:
        return dict(base, running=False, status="")
    try:
        _validate_resource(client, "client name")
    except ValueError as e:
        response.status_code = 500
        return dict(base, running=True, status="", message=str(e))

    raw_console = None
    try:
        raw_console = bareos.bsock.DirectorConsole(
            address=CONFIG_DIRECTOR_ADDRESS,
            port=CONFIG_DIRECTOR_PORT,
            dirname=CONFIG_DIRECTOR_NAME,
            name=current_user.username,
            password=bareos.bsock.Password(current_user.password),
        )
        result = raw_console.call("status client=%s" % client)
    except Exception as e:
        # An FD that is unreachable mid-job is a valid answer, not a 5xx.
        return dict(base, running=True, status="", message=str(e))
    finally:
        if raw_console is not None:
            try:
                raw_console.close()
            except Exception:
                pass
    text = result.decode("utf-8", "replace") if isinstance(result, bytes) else str(result)
    return dict(base, running=True, status=text)


@app.get("/control/jobs", tags=["jobcontrol", "control", "jobs"])
def read_all_jobs_status(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    limit: Optional[int] = Query(None, title="Result items limit", gt=1),
    offset: Optional[int] = Query(None, title="Result items offset", gt=0),
    jobQuery: Optional[jobQuery] = Body(None, title="Query parameter"),
):
    return list_catalog_items(
        itemType="jobs",
        current_user=current_user,
        response=response,
        limit=limit,
        offset=offset,
        jobQuery=jobQuery,
        hasCountOption="yes",
    )


@app.delete("/control/jobs/{job_id}", tags=["jobcontrol", "control", "jobs"])
def delete_job(
    *,
    job_id: int = Path(..., title="The ID of job to delete", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Delete job record from catalog
    """
    # Director gives no success nor failed information
    # We implemente validation here (check if job exists before and after deletion)
    jobStatusResponse = read_job_status(
        job_id=job_id, response=response, current_user=current_user
    )
    if not "jobid" in jobStatusResponse:
        response.status_code = 404
        return {
            "message": "No job with id %d found on director %s."
            % (job_id, current_user.directorName)
        }
    # delete a specific job record given bei jobid
    deleteCommand = "delete jobid=%d" % job_id
    try:
        result = current_user.jsonDirector.call(deleteCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not delete jobid %d on director %s. Message: '%s'"
            % (job_id, current_identity.directorName, e)
        }
    jobStatusResponse = read_job_status(
        job_id=job_id, response=response, current_user=current_user
    )
    if "jobid" in jobStatusResponse:
        response.status_code = 500
        return {
            "message": "Job with id %d still exists on director %s. Delete failed"
            % (job_id, current_user.directorName)
        }
    response.status_code = 200
    return {"message": "Job %d succesfully deleted." % job_id}


@app.get("/control/jobs/logs/{job_id}", tags=["jobcontrol", "control", "jobs"])
def read_one_job_log(
    *,
    job_id: int = Path(..., title="The ID of job to get the logs", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Read logs from a specific job defined by jobid
    Returns output of command _list joblog jobid=id_
    """
    result = None
    listCommand = "list joblog jobid=%d" % job_id
    try:
        result = current_user.jsonDirector.call(listCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read joblogs on director %s. Message: '%s'"
            % (current_user.directorName, e)
        }
    if result and "joblog" in result:
        totalItems = len(result["joblog"])
        return {"totalItems": totalItems, "joblog": result["joblog"]}
    else:
        response.status_code = 404
        return {"message": "Joblogs Job with ID {jobid} not found".format(jobid=job_id)}


@app.get("/control/jobs/files/{job_id}", tags=["jobcontrol", "control", "jobs"])
def read_files_of_job(
    *,
    job_id: int = Path(..., title="The ID of job to get the files", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Read files from a specific job defined by jobid
    Returns output of command _list joblog jobid=id_
    """
    result = None
    listCommand = "list files jobid=%d" % job_id
    try:
        result = current_user.jsonDirector.call(listCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read jobfiles on director %s. Message: '%s'"
            % (current_user.directorName, e)
        }
    if result and "filenames" in result:
        totalItems = len(result["filenames"])
        return {"totalItems": totalItems, "filenames": result["filenames"]}
    else:
        response.status_code = 404
        return {
            "message": "Files for job with ID {jobid} not found".format(jobid=job_id)
        }


#### JobDefs


@app.post("/confguration/jobdefs", tags=["jobdefs", "configuration"])
def post_jobdef(
    *,
    jobDef: jobDefs = Body(..., title="Jobdef resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new jobdefs resource.
    Console command used: _configure add jobdefs_
    """
    return configure_add_standard_component(
        componentDef=jobDef,
        response=response,
        current_user=current_user,
        componentType="jobdefs",
    )


@app.get("/configuration/jobdefs", tags=["jobdefs", "configuration"])
def read_all_jobdefs(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show jobdefs_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="jobdefs",
        verbose=verbose,
    )


@app.get("/configuration/jobdefs/{jobdefs_name}", tags=["jobdefs", "configuration"])
def read_jobdef_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    jobdefs_name: str = Path(..., title="JobDef name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show jobdefs_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="jobdefs",
        byName=jobdefs_name,
        verbose=verbose,
    )


#### Job Resource


@app.get("/configuration/jobs", tags=["jobs", "configuration"])
def read_all_jobs(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show jobs_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response, current_user=current_user, itemType="jobs", verbose=verbose
    )


@app.get("/configuration/jobs/{jobs_name}", tags=["jobs", "configuration"])
def read_job_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    jobs_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show jobs_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="jobs",
        byName=jobs_name,
        verbose=verbose,
    )


@app.post("/configuration/jobs", tags=["jobs", "configuration"])
def post_job(
    *,
    jobDef: jobResource = Body(..., title="Job resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new job resource.
    Console command used: _configure add job_

    """
    return configure_add_standard_component(
        componentDef=jobDef,
        response=response,
        current_user=current_user,
        componentType="job",
    )


@app.put("/configuration/jobs/{jobs_name}", tags=["jobs", "configuration"])
def put_job(
    *,
    jobs_name: str = Path(..., title="Job (name) to modify"),
    jobDef: jobUpdate = Body(..., title="Desired job state"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Modify a job resource (partial, merge semantics).

    Same file-based mechanism as the client endpoints (bconsole has no
    `configure modify`): the fields you send are merged into the resource file
    at <ResourceDir>/job/<name>.conf and the director is reloaded; omitted
    directives are preserved. The job must already exist — use
    POST /configuration/jobs to create. The URL {jobs_name} is authoritative;
    a `name` in the body must match it (there is no rename).
    """
    return _modify_resource(
        response=response,
        current_user=current_user,
        componentType="job",
        resourceType="Job",
        name_raw=jobs_name,
        data=jobDef.dict(),
        aliases=_JOB_ALIASES,
    )


@app.delete("/configuration/jobs/{jobs_name}", tags=["jobs", "configuration"])
def delete_job_config(
    *,
    jobs_name: str = Path(..., title="Job (name) to delete"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Delete a job resource from the director.

    Removes <ResourceDir>/job/<name>.conf and reloads. If a running/scheduled
    job or another resource still depends on it the reload reports the error
    and the delete is rolled back.
    """
    return _delete_resource(
        response=response,
        current_user=current_user,
        componentType="job",
        resourceType="Job",
        name_raw=jobs_name,
    )


### Volumes


@app.get("/control/volumes", tags=["volumes", "control"])
def read_volumes(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    limit: Optional[int] = Query(None, title="Result items limit", gt=0),
    offset: Optional[int] = Query(None, title="Result items offset", gt=0),
    myQuery: Optional[volumeQuery] = Body(None, title="Query parameter"),
):
    queryDict = {}
    countDict = {}
    responseDict = {}
    results = {}
    results["volumes"] = {}
    volumeKeyName = "volumes"
    volumeCommand = "llist volumes"
    countCommand = "list volumes"
    if myQuery is not None:
        queryDict = myQuery.dict()
    for q in queryDict:
        if queryDict[q] is not None:
            volumeCommand += " %s=%s" % (q, str(queryDict[q]))
            countCommand += " %s=%s" % (q, str(queryDict[q]))
    countCommand += " count"
    if limit is not None:
        volumeCommand += " limit=%d" % limit
    if offset is not None:
        volumeCommand += " offset=%d" % offset
    # if volume name is in queryDict, we have to remove the other filters
    # and use a different comman
    if "volume" in queryDict and queryDict["volume"] is not None:
        volumeKeyName = "volume"
        volumeCommand = "llist volume=%s" % queryDict["volume"]
        countCommand = None
    try:
        responseDict = current_user.jsonDirector.call(volumeCommand)
        if countCommand is not None:
            countDict = current_user.jsonDirector.call(countCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read volume list from director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    if "volumes" in responseDict:
        counter = 0
        # countDict/response dict has different structures, if filtered by pool or not
        if isinstance(countDict["volumes"], dict):
            results["volumes"] = responseDict[volumeKeyName]
            for p in countDict["volumes"]:
                counter += int(countDict["volumes"][p][0]["count"])
        else:
            # check for empty pool
            if len(responseDict[volumeKeyName]) == 0:
                response.status_code = 404
                return {"message": "Nothing found. Command: %s" % volumeCommand}
            poolName = responseDict[volumeKeyName][0]["pool"]
            # print(responseDict[volumeKeyName])
            results["volumes"][poolName] = responseDict[volumeKeyName]
            counter = int(countDict["volumes"][0]["count"])
        results["totalItems"] = counter
        foundItems = len(responseDict)
    elif "volume" in responseDict and "pool" in responseDict["volume"]:
        foundItems = 1
        poolName = responseDict["volume"]["pool"]
        results["totalItems"] = 1
        results["volumes"] = {poolName: [responseDict["volume"]]}
    else:
        response.status_code = 404
        return {"message": "nothing found for command: %s" % volumeCommand}

    if foundItems > 0:
        # check for limit / offset
        if limit is not None:
            results["limit"] = limit
        if offset is not None:
            results["offset"] = offset
        return results
    else:
        response.status_code = 404
        return {"message": "No volumes found."}


@app.get("/control/volumes/{volume_id}", tags=["volumes", "control"])
def read_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    volume_id: int = Path(..., title="Volume ID to look for", gt=0, example=1),
    volumeQuery: Optional[volumeQuery] = Body(None, title="Query parameter"),
):
    volumeCommand = "llist volumes"
    try:
        responseDict = current_user.jsonDirector.call(volumeCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read volume list from director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    if "volumes" in responseDict:
        for p in responseDict["volumes"]:
            for v in responseDict["volumes"][p]:
                if v["mediaid"] == str(volume_id):
                    response.status_code = 200
                    return v
    response.status_code = 404
    return {"message": "No volume with id %d found" % volume_id}


@app.post("/control/volumes", status_code=200, tags=["volumes", "control"])
def label_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    volumeLabel: volumeLabelDef = Body(..., title="Volume label properties"),
):
    """
    Label a new volume using the _label_" command
    """
    responseDict = {}
    labelCommand = "label"
    labelCommand += parseCommandOptions(volumeLabel.dict())
    try:
        responseDict = current_user.jsonDirector.call(labelCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not label volume on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    return responseDict


@app.patch("/control/volumes/{volume_name}", tags=["volumes", "control"])
def update_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    volume_name: str = Path(..., title="Volume Name to update", example="Full-1742"),
    volumeProps: volumeProperties = Body(..., title="Volume properties"),
):
    """
    Update a volume
    TODO: verify, that parameter are quoted correct
    """
    responseDict = {}
    updateCommand = "update volume=%s" % volume_name
    updateCommand += parseCommandOptions(volumeProps.dict())
    # print(updateCommand)
    try:
        responseDict = current_user.jsonDirector.call(updateCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not update volume on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    # Director delivers empty response, we want to return the changed volume's properties
    volQuery = volumeQuery()
    volQuery.volume = volume_name
    responseDict = read_volumes(
        response=response,
        current_user=current_user,
        myQuery=volQuery,
        limit=None,
        offset=None,
    )
    # TODO: responseDict is structured: {volumes:{poolname:[{volume}]}} - we just want to return the volume without list and pool dict around
    return responseDict


@app.put("/control/volumes/move", status_code=200, tags=["volumes", "control"])
def move_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    moveParams: volumeMove = Body(..., title="Volume move parameters"),
):
    """
    Move a volume, using the _move_ command
    TODO: handle encrypt flag
    """
    responseDict = {}
    updateCommand = "move"
    updateCommand += parseCommandOptions(moveParams.dict())
    # print (updateCommand)
    try:
        responseDict = current_user.jsonDirector.call(updateCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not move volumes on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    # Director delivers empty response
    return responseDict


@app.put("/control/volumes/export", status_code=200, tags=["volumes", "control"])
def export_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    exportParams: volumeExport = Body(..., title="Volume Export parameters"),
):
    """
    Export volumes the _export_ command
    """
    responseDict = {}
    updateCommand = "export"
    updateCommand += parseCommandOptions(exportParams.dict())
    # print(updateCommand)
    try:
        responseDict = current_user.jsonDirector.call(updateCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not export volumes on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    # Director delivers empty response
    response.status_code = 200
    return responseDict


@app.put("/control/volumes/import", status_code=200, tags=["volumes", "control"])
def import_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    importParams: volumeImport = Body(..., title="Volume import parameters"),
):
    """
    import volumes the _import_ command
    """
    responseDict = {}
    updateCommand = "import"
    updateCommand += parseCommandOptions(importParams.dict())
    # print(updateCommand)
    try:
        responseDict = current_user.jsonDirector.call(updateCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not import volumes on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    # Director delivers empty response
    response.status_code = 200
    return responseDict


@app.put("/control/volumes/{volume_name}", status_code=200, tags=["volumes", "control"])
def relabel_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    volume_name: str = Path(
        ..., title="Old Volume Name to relabel", example="Full-1742"
    ),
    volumeRelabel: volumeRelabelDef = Body(..., title="New label properties"),
):
    """
    Relabel a volume, using the _relabel_ command
    TODO: handle encrypt flag
    """
    responseDict = {}
    updateCommand = "relabel oldvolume=%s" % volume_name
    updateCommand += parseCommandOptions(volumeRelabel.dict())
    # print(updateCommand)
    try:
        responseDict = current_user.jsonDirector.call(updateCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not relabel volume on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    # Director delivers empty response
    response.status_code = 200
    return responseDict


@app.delete(
    "/control/volumes/{volume_name}", status_code=204, tags=["volumes", "control"]
)
def delete_volume(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    volume_name: str = Path(..., title="Volume Name to delete", example="Full-1742"),
):
    """
    Delete a volume from catalog using the _delete volume_ command.
    """
    responseDict = {}
    deleteCommand = "delete volume=%s yes" % volume_name
    try:
        responseDict = current_user.jsonDirector.call(deleteCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not delete volume on director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    # Director delivers empty response
    response.status_code = 204
    return responseDict


### Pools


@app.get("/configuration/pools", tags=["pools", "configuration"])
def read_all_pools(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show pools_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response, current_user=current_user, itemType="pools", verbose=verbose
    )


@app.get("/configuration/pools/{pools_name}", tags=["pools", "configuration"])
def read_pool_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    pools_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show pools_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="pools",
        byName=pools_name,
        verbose=verbose,
    )


@app.post("/configuration/pools", tags=["pools", "configuration"])
def post_pool(
    *,
    poolDef: poolResource = Body(..., title="pool resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new pool resource.
    Console command used: _configure add pool_
    """
    return configure_add_standard_component(
        componentDef=poolDef,
        response=response,
        current_user=current_user,
        componentType="pool",
    )


@app.get("/control/pools", status_code=200, tags=["pools", "control"])
def read_all_pools(
    response: Response,
    current_user: User = Depends(get_current_user),
    name: Optional[str] = None,
):
    """
    Read settings for all pools or just one pool by name from catalog.
    Built on console command _llist pool_
    """
    listCommand = ""
    if name:
        listCommand = "llist pool=%s" % name
    else:
        listCommand = "llist pools"
    # print(listCommand)
    try:
        responseDict = current_user.jsonDirector.call(listCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read pool list from director %s. Message: '%s'"
            % (CONFIG_DIRECTOR_NAME, e)
        }
    if "pools" in responseDict:
        totalItems = len(responseDict["pools"])
        return {"totalItems": totalItems, "pools": responseDict["pools"]}
    else:
        response.status_code = 404
        return {"message": "No pools found."}


@app.get("/control/pools/{pool_id}", tags=["pools", "control"])
def read_pool(
    *,
    pool_id: int = Path(..., title="The ID of pool to get", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Read catalog information abour just one pool by id.
    Built on console command _llist pool_

    **Warning** Director does not support direct query by _id_ we query all pools and filter the result.
    Maybe more time consuming than expected in large settings.
    """
    allpools = read_all_pools(response, current_user)
    result = None
    for c in allpools["pools"]:
        if c["poolid"] == str(pool_id):
            result = c
            break
    if result:
        return result
    else:
        response.status_code = 404
        return {
            "message": "pool with pool ID {pool_id} not found".format(pool_id=pool_id)
        }
    return {"item_id": item_id}


### Schedules


@app.get("/configuration/schedules", tags=["schedules", "configuration"])
def read_all_schedules(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show schedules_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="schedules",
        verbose=verbose,
    )


@app.get(
    "/configuration/schedules/{schedules_name}", tags=["schedules", "configuration"]
)
def read_schedule_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    schedules_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show schedules_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="schedules",
        byName=schedules_name,
        verbose=verbose,
    )


@app.post("/configuration/schedules", tags=["schedules", "configuration"])
def create_schedule(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    scheduleDef: scheduleResource = Body(..., title="Name for new schedule"),
):
    """
    Create a new schedule resource.
    Console command used _configure add schedule_
    """
    return configure_add_standard_component(
        response=response,
        componentDef=scheduleDef,
        componentType="schedule",
        current_user=current_user,
    )


@app.put(
    "/control/schedules/enable/{schedule_name}",
    status_code=204,
    tags=["schedules", "control"],
)
def enable_schedule(
    *,
    schedule_name: str = Path(..., title="The schedule (name) to enable"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    (result, jsonMessage) = switch_resource(
        response=response,
        current_user=current_user,
        resourceName=schedule_name,
        componentType="schedule",
        enable=True,
    )
    return jsonMessage


@app.put(
    "/control/schedules/disable/{schedule_name}",
    status_code=204,
    tags=["schedules", "control"],
)
def disable_schedule(
    *,
    schedule_name: str = Path(..., title="The schedule (name) to disable"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    (result, jsonMessage) = switch_resource(
        response=response,
        current_user=current_user,
        resourceName=schedule_name,
        componentType="schedule",
        enable=False,
    )
    return jsonMessage


### Storages


@app.get("/configuration/storages", tags=["storages", "configuration"])
def read_all_storages(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show storages_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="storages",
        verbose=verbose,
    )


@app.get("/configuration/storages/{storages_name}", tags=["storages", "configuration"])
def read_storage_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    storages_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show storages_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="storages",
        byName=storages_name,
        verbose=verbose,
    )


@app.post("/configuration/storage", tags=["storages", "configuration"])
def post_storage(
    *,
    storageDef: storageResource = Body(..., title="storage resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new storage resource.
    Console command used: _configure add storage_
    """
    return configure_add_standard_component(
        response=response,
        componentDef=storageDef,
        componentType="storage",
        current_user=current_user,
    )


### Users, profiles, consoles


@app.get("/configuration/users", tags=["users", "configuration"])
def read_all_users(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all users resources. Built on console command _show users_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response, current_user=current_user, itemType="users", verbose=verbose
    )


@app.get("/configuration/users/{users_name}", tags=["users", "configuration"])
def read_user_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    users_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show users_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="users",
        byName=users_name,
        verbose=verbose,
    )


@app.post("/configuration/users", tags=["users", "configuration"])
def post_user(
    *,
    userDef: userResource = Body(..., title="user resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new Bareos user resource.
    Console command used: _configure add user_

    """
    return configure_add_standard_component(
        response=response,
        componentDef=userDef,
        componentType="user",
        current_user=current_user,
    )


@app.get("/configuration/profiles", tags=["profiles", "configuration"])
def read_all_profiles(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show profiles_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="profiles",
        verbose=verbose,
    )


@app.get("/configuration/profiles/{profiles_name}", tags=["profiles", "configuration"])
def read_client_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    profiles_name: str = Path(..., title="Client name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show profiles_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="profiles",
        byName=profiles_name,
        verbose=verbose,
    )


@app.post("/configuration/profiles", tags=["users", "configuration"])
def post_profile(
    *,
    profileDef: profileResource = Body(..., title="profile resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new Bareos profile resource.
    Console command used: _configure add profile_

    """
    return configure_add_standard_component(
        response=response,
        componentDef=profileDef,
        componentType="profile",
        current_user=current_user,
    )


@app.get("/configuration/consoles", tags=["consoles", "configuration"])
def read_all_consoles(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show consoles_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="consoles",
        verbose=verbose,
    )


@app.get("/configuration/consoles/{consoles_name}", tags=["consoles", "configuration"])
def read_console_by_name(
    *,
    response: Response,
    current_user: User = Depends(get_current_user),
    consoles_name: str = Path(..., title="Console name to look for"),
    verbose: Optional[bareosBool] = Query("yes", title="Verbose output"),
):
    """
    Read all jobdef resources. Built on console command _show consoles_.

    Needs at least Bareos Version >= 20.0.0
    """
    return show_configuration_items(
        response=response,
        current_user=current_user,
        itemType="consoles",
        byName=consoles_name,
        verbose=verbose,
    )


@app.post("/configuration/consoles", tags=["users", "configuration"])
def post_console(
    *,
    consoleDef: consoleResource = Body(..., title="console resource"),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new Bareos console resource.
    Console command used: _configure add console_

    """
    return configure_add_standard_component(
        response=response,
        componentDef=consoleDef,
        componentType="console",
        current_user=current_user,
    )


### Director


@app.get("/control/directors/version", tags=["directors", "control"])
def read_director_version(
    *, response: Response, current_user: User = Depends(get_current_user)
):
    """
    Read director version. Command used: _version_
    """
    result = None
    dirCommand = "version"
    try:
        result = current_user.jsonDirector.call(dirCommand)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Could not read version from director"
        )
    if result and "version" in result:
        return result["version"]
    else:
        response.status_code = 404
        return {"message": "No version info returned"}


@app.get("/control/directors/time", tags=["directors", "control"])
def read_director_time(
    *, response: Response, current_user: User = Depends(get_current_user)
):
    """
    Read director time. Command used: _time_
    """
    result = None
    dirCommand = "time"
    try:
        result = current_user.jsonDirector.call(dirCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not read director time %s. Message: '%s'"
            % (current_user.directorName, e)
        }
    if result and "time" in result:
        return result["time"]
    else:
        response.status_code = 404
        return {"message": "No time info returned"}


@app.put("/control/directors/reload", tags=["directors", "control"])
def read_director_time(
    *, response: Response, current_user: User = Depends(get_current_user)
):
    """
    Reload director configuration from files. Command used: _reload_
    """
    result = None
    dirCommand = "reload"
    try:
        result = current_user.jsonDirector.call(dirCommand)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not reload director %s. Message: '%s'"
            % (current_user.directorName, e)
        }
    if result and "reload" in result:
        return result["reload"]
    else:
        response.status_code = 500
        return result


# ---------- BVFS (Bacula Virtual File System) ----------
# Bareos catalog tables exposing the backup contents as a navigable tree.
# Together with /control/jobs/restore-bvfs this is the proper multi-select
# restore path — the legacy /control/jobs/restore can only handle ONE file
# OR ONE directory at a time (the Director protocol literally doesn't accept
# pipe-separated or repeated path arguments).
#
# Auth: the same OAuth2 bearer token used by the other endpoints. All commands
# are dispatched via the user's cached jsonDirector session.

import re
import time
import random

# Input validators. The Director's bconsole grammar is space-separated
# key=value pairs, so unsanitized user input can override existing args (e.g.
# `path=/etc/ jobid=666 client=victim`) and reach commands the user's Console
# Profile would normally deny. We validate every user-controlled field with a
# strict regex before interpolation.

_RE_JOBIDS = re.compile(r"^[0-9]+(,[0-9]+)*$")
_RE_RESOURCE = re.compile(r"^[A-Za-z0-9._-]+$")  # Bareos resource-name charset
_RE_BVFS_PATH = re.compile(r"^/[^\s=;]*$")       # bvfs_ls* path: abs, no ws/=/;
_RE_WHERE = re.compile(r"^/[^\s=;]*$")           # restore where: same as path
_REPLACE_VALUES = {"always", "never", "ifolder", "ifnewer"}


def _bad_request(response, msg):
    response.status_code = 400
    return {"detail": msg}


def _validate_jobids(value):
    if not value or not _RE_JOBIDS.match(value):
        raise ValueError("jobid(s) must be a comma-separated list of integers")
    return value


def _validate_resource(name, label="name"):
    if not name or not _RE_RESOURCE.match(name):
        raise ValueError("%s must match [A-Za-z0-9._-]+" % label)
    return name


def _validate_bvfs_path(path):
    if not _RE_BVFS_PATH.match(path):
        raise ValueError(
            "path must be absolute and contain no whitespace, '=', or ';'"
        )
    if not path.endswith("/"):
        path = path + "/"
    return path


def _validate_where(where):
    if not _RE_WHERE.match(where):
        raise ValueError(
            "where must be absolute and contain no whitespace, '=', or ';'"
        )
    return where


def _validate_id_list(ids, label):
    out = []
    for x in ids:
        if not isinstance(x, int) or x < 1:
            raise ValueError("%s entries must be positive integers" % label)
        out.append(str(x))
    return ",".join(out)


def _validate_replace(value):
    if value is None:
        return None
    s = value.value if hasattr(value, "value") else value
    if s not in _REPLACE_VALUES:
        raise ValueError("replace must be one of %s" % sorted(_REPLACE_VALUES))
    return s


def _bvfs_call(current_user, cmd):
    """Run a .bvfs_* (or restore) command and return the JSON director output."""
    return current_user.jsonDirector.call(cmd)


@app.post("/control/bvfs/update", tags=["bvfs", "control"])
def bvfsUpdate(
    *,
    jobid: Optional[int] = Query(
        None, title="JobId to refresh the path cache for. Omit to refresh everything.", ge=1
    ),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Refresh the BVFS path cache (`.bvfs_update`). Idempotent — Bareos skips
    work if the cache for the requested job is already current. Run this once
    per fresh job before browsing dirs/files.
    """
    cmd = ".bvfs_update"
    if jobid is not None:
        cmd += " jobid=%d" % jobid
    try:
        _bvfs_call(current_user, cmd)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not run %s on director %s. Message: '%s'"
            % (cmd, current_user.directorName, e)
        }
    return {"updated": True, "jobid": jobid}


@app.get("/control/bvfs/dirs", tags=["bvfs", "control"])
def bvfsLsDirs(
    *,
    jobid: str = Query(
        ...,
        title="JobId(s) to query, comma-separated. Use /control/bvfs/get_jobids to chain Full→Diff→Inc.",
        example="3",
        regex=r"^[0-9]+(,[0-9]+)*$",
    ),
    path: str = Query(
        "/",
        title="Directory path to list (must end in / when browsing a subdir; root is /).",
        example="/",
    ),
    limit: int = Query(2000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    autoupdate: bool = Query(
        True, title="Run .bvfs_update first so cold jobs return data immediately."
    ),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    List immediate subdirectories of `path` for the given JobIds
    (`.bvfs_lsdirs`). Returns rows of (pathid, fileid, jobid, lstat, name).
    """
    try:
        jobid = _validate_jobids(jobid)
        path = _validate_bvfs_path(path)
    except ValueError as e:
        return _bad_request(response, str(e))
    try:
        if autoupdate:
            _bvfs_call(current_user, ".bvfs_update jobid=%s" % jobid)
        result = _bvfs_call(
            current_user,
            ".bvfs_lsdirs jobid=%s path=%s limit=%d offset=%d" % (jobid, path, limit, offset),
        )
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not list dirs at %s for jobid=%s: %s" % (path, jobid, e)
        }
    return result


@app.get("/control/bvfs/files", tags=["bvfs", "control"])
def bvfsLsFiles(
    *,
    jobid: str = Query(
        ...,
        title="JobId(s), comma-separated",
        example="3",
        regex=r"^[0-9]+(,[0-9]+)*$",
    ),
    path: str = Query(..., title="Directory path to list files in", example="/etc/"),
    limit: int = Query(2000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    autoupdate: bool = Query(True),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    List files directly in `path` (`.bvfs_lsfiles`). Returns rows with the
    `fileid` you need to pass to `/control/jobs/restore-bvfs`.
    """
    try:
        jobid = _validate_jobids(jobid)
        path = _validate_bvfs_path(path)
    except ValueError as e:
        return _bad_request(response, str(e))
    try:
        if autoupdate:
            _bvfs_call(current_user, ".bvfs_update jobid=%s" % jobid)
        result = _bvfs_call(
            current_user,
            ".bvfs_lsfiles jobid=%s path=%s limit=%d offset=%d" % (jobid, path, limit, offset),
        )
    except Exception as e:
        response.status_code = 500
        return {
            "message": "Could not list files at %s for jobid=%s: %s" % (path, jobid, e)
        }
    return result


@app.get("/control/bvfs/get_jobids", tags=["bvfs", "control"])
def bvfsGetJobIds(
    *,
    jobid: int = Query(..., title="Pivot JobId; returns the chain needed to restore it.", ge=1),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Resolve the JobId chain (Full→Diff→Inc) needed to restore the requested
    JobId (`.bvfs_get_jobids`). Pass the resulting `jobids` string verbatim to
    /control/bvfs/dirs and /control/jobs/restore-bvfs.
    """
    try:
        result = _bvfs_call(current_user, ".bvfs_get_jobids jobid=%d" % jobid)
    except Exception as e:
        response.status_code = 500
        return {"message": "Could not resolve jobid chain for %d: %s" % (jobid, e)}
    return result


@app.post("/control/jobs/restore-bvfs", tags=["jobcontrol", "control", "jobs", "bvfs"])
def runRestoreJobBvfs(
    *,
    jobControl: restoreBvfsControl = Body(
        ..., title="BVFS-driven multi-select restore", embed=True
    ),
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """
    Multi-select restore driven by BVFS catalog IDs:
      1. .bvfs_restore  — materialize a private temp table holding the chosen
         file/dir ids
      2. restore file=?<table>  — kick off ONE restore job that consumes the
         temp table

    Returns the spawned JobId. The legacy /control/jobs/restore endpoint can
    only restore a single file or single directory; this one handles the
    arbitrary multi-pick case Dr. Acula needs.
    """
    if not jobControl.fileids and not jobControl.dirids:
        response.status_code = 422
        return {"detail": "Either fileids or dirids must be non-empty"}

    # Validate every user-controlled field BEFORE building any bconsole command.
    # bconsole splits on whitespace, so unescaped values could inject extra args
    # and bypass the user's Console Profile ACL.
    try:
        jobids = _validate_jobids(jobControl.jobids)
        client = _validate_resource(jobControl.client, "client")
        restoreclient = (
            _validate_resource(jobControl.restoreclient, "restoreclient")
            if jobControl.restoreclient
            else None
        )
        where = _validate_where(jobControl.where) if jobControl.where else None
        replace = _validate_replace(jobControl.replace)
        fileid_arg = (
            _validate_id_list(jobControl.fileids, "fileids")
            if jobControl.fileids
            else ""
        )
        dirid_arg = (
            _validate_id_list(jobControl.dirids, "dirids")
            if jobControl.dirids
            else ""
        )
    except ValueError as e:
        return _bad_request(response, str(e))

    # Bareos requires the BVFS temp-table name to match `^b2[0-9]+$` strictly
    # (core/src/cats/bvfs.cc CheckTemp — literal "b2" then pure digits, no
    # underscores/hyphens/letters). Pack timestamp_ms + random_4d into one
    # integer suffix for per-request uniqueness.
    table_name = "b2%d%04d" % (int(time.time() * 1000), random.randint(0, 9999))

    bvfs_parts = [
        ".bvfs_restore",
        "path=%s" % table_name,
        "jobid=%s" % jobids,
    ]
    if fileid_arg:
        bvfs_parts.append("fileid=" + fileid_arg)
    if dirid_arg:
        bvfs_parts.append("dirid=" + dirid_arg)
    bvfs_cmd = " ".join(bvfs_parts)

    try:
        _bvfs_call(current_user, bvfs_cmd)
    except Exception as e:
        response.status_code = 500
        return {"message": "Could not prepare BVFS restore table: %s. Cmd: %s" % (e, bvfs_cmd)}

    # Trigger the restore via the temp table reference "?<name>".
    restore_parts = [
        "restore",
        "file=?%s" % table_name,
        "client=%s" % client,
        "yes",
    ]
    if restoreclient:
        restore_parts.append("restoreclient=%s" % restoreclient)
    if where:
        restore_parts.append("where=%s" % where)
    if replace:
        restore_parts.append("replace=%s" % replace)
    restore_cmd = " ".join(restore_parts)

    try:
        result = _bvfs_call(current_user, restore_cmd)
    except Exception as e:
        response.status_code = 500
        return {
            "message": "BVFS table prepared but restore start failed: %s. Cmd: %s" % (e, restore_cmd)
        }
    if "run" in result and "jobid" in result["run"]:
        return {"jobid": int(result["run"]["jobid"]), "table": table_name}
    response.status_code = 500
    return {
        "message": "Restore command returned no jobid. Result: %s" % result,
        "table": table_name,
    }
