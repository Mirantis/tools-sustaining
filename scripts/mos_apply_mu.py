#!/usr/bin/env python
# Copyright 2013 - 2015 Mirantis, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json
import sys
import urllib2
import subprocess
import os

try:
    from keystoneclient.v2_0 import client
except ImportError:
    print ("Can't find keystone-client, "
           "this script must be only used on Fuel-node")
    sys.exit(10)

username = 'admin'
password = 'admin'
tenant = 'admin'
auth = 'http://127.0.0.1:5000/v2.0'
logfile = 'mos_apply_mu.log'

env_id = 0
all_envs = False
try_offline = False
really = False
check = False

master_ip = "10.20.0.2"
path = "custom.pkg"
install_custom = False
pkgs = None
dest = "/var/www/nailgun/updates/custom/"


def arg_parse():
    global env_id
    global all_envs
    global try_offline
    global really
    global username
    global password
    global tenant
    global path
    global install_custom
    global repo_install
    global master_ip
    global check

    usage = """
Tool to apply maintenance updates and custom packages into nodes.
Usage:
    python mos_apply_mu.py --env-id|--all-envs --check|--update

Required arguments:

    --env-id            ID of operational environment which needs to be updated
                OR
    --all-envs          Update all operational environments

    --update            Make real update (without this nothing will be updated)
                OR
    --check             Check status of selected nodes

Optional arguments:

    --master-ip         IP-Address of Fuel-master node
                            default: 10.20.0.2
    --offline           Add to update nodes which are currently offline in fuel
                            (can cause significant timeouts)
    --user              Username used in Fuel-Keystone authentication
                            default: admin
    --pass              Password suitable to username
                            default: admin
    --tenant            Suitable tenant
                            default: admin
    --file              Name of the config file in json-format with list of
                        custom packages to download and install


Examples:

    python mos_apply_mu.py --env-id=11 --user=op --pass=V3ryS3Cur3 \
                           --master-ip="10.100.15.2"

    Inspects Fuel configuration with op's credentials and shows which nodes
    will be updated in environment (cluster) #11

    python mos_apply_mu.py --env-id=11 --user=op --pass=V3ryS3Cur3 \
                           --update --master-ip="10.100.15.2"

    Makes real update on nodes in environment #11

    python mos_apply_mu.py --env-id=11 --user=op --pass=V3ryS3Cur3 --check

    Checks current state of update process on nodes in environment #11
    States may be the following (separate for each node):
        STARTED - script has been started and it's still working
        PACKAGES_INSTALLING - script is installing custom packages
        REPO_UPD=OK;PKGS=0 of 2 INSTALLED - execution is over,
            maintenance update has been successfuly installed
            but installation of custom packages was unsuccessful

    To get detailed log examine /var/log/mos_apply_mu.log on remote nodes.

Questions: dmeltsaykin@mirantis.com

Mirantis, 2015
"""

    for cmd in sys.argv[1:]:
        if '--env-id' in cmd:
            env_id = int(cmd.split('=')[1])
        if '--user' in cmd:
            username = cmd.split('=')[1]
        if '--pass' in cmd:
            password = cmd.split('=')[1]
        if '--tenant' in cmd:
            tenant = cmd.split('=')[1]
        if '--all-envs' in cmd:
            all_envs = True
        if '--offline' in cmd:
            try_offline = True
        if '--check' in cmd:
            check = True
        if '--update' in cmd:
            really = True
        if '--file' in cmd:
            path = cmd.split('=')[1]
        if '--with-custom' in cmd:
            install_custom = True
        if '--master-ip' in cmd:
            master_ip = cmd.split('=')[1]

    if (env_id > 0) and (all_envs):
        print ("You should only select either --env-id or --all-envs.")
        print (usage)
        sys.exit(5)
    if (env_id == 0) and (not all_envs):
        print ("At least one option (env-id or all-envs) must be set.")
        print (usage)
        sys.exit(6)
    if really and check:
        print ("You should use either --check or --update. Not both.")
        print (usage)
        sys.exit(7)


def get_downloads_list():
    global pkgs
    try:
        file = open(path, 'r')
        pkgs = json.load(file)
        file.close()
    except:
        return None
    return True


def packages_download():
    #check if dst dir exists if not create it (and others)
    try:
        os.makedirs(dest)
    except os.error as err:
        if err.args[0] != 17:
            print ("Error during creating directory {0}: {1}".format(
                dest, err.args[1]))
            return (None)

    retval = 0
    for pkg in pkgs.values():
        for t in pkg:
            cmd = "wget -c -P{0} \"{1}\"".format(dest, t)
            print ("Running: {0}".format(cmd))
            retval += os.system(cmd)

    if retval != 0:
        print ("Some downloads are failed!")
    return (retval)


def get_nodes():
    req = urllib2.Request('http://127.0.0.1:8000/api/v1/nodes/')
    req.add_header('X-Auth-Token', token)
    nodes = json.load(urllib2.urlopen(req))
    return nodes


def get_operational_envs(nodes, env_list):
    for node in nodes:
        if (node['status'] == "ready"):
            if try_offline:
                env_list.add(node['cluster'])
            elif node['online']:
                env_list.add(node['cluster'])


def check_status(ip):
    """Checks state of node by reading last line of status-file"""
    cmd = ["ssh", ip, "tail -n1 /var/log/mos_apply_mu.status"]
    proc = subprocess.Popen(cmd, stdin=None, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    proc.wait()
    if proc.returncode == 0:
        state = proc.communicate()[0]
        print("Node {0} state: {1}".format(ip, state))
        return True
    else:
        print("Node {0} FAILURE!".format(ip))
        return False


def do_node_update(nodes, env_list):
    to_update = set()
    for env in env_list:
        for node in nodes:
            if node['cluster'] == env:
                if try_offline:
                    to_update.add((node['ip'], node['os_platform']))
                elif node['online']:
                    to_update.add((node['ip'], node['os_platform']))

    print ("Selected nodes: " + ", ".join([x[0] for x in to_update]))
    packages_to_install = get_downloads_list()
    if really:
        if packages_to_install is not None:
            packages_download()
        else:
            print ("Unable to get packages list from file {0}".format(path))

    for ip, os_version in to_update:
        send_shell_script(ip, os_version)
        if check:
            check_status(ip)


def get_md5_from_file(file):
    """ Gets md5 checksum from file by calling external tool."""
    run = subprocess.Popen(["md5sum", file], stdin=None,
                           stdout=subprocess.PIPE, stderr=None)
    run.wait()

    if run.returncode == 0:
        md5 = run.communicate()[0].split('  ')[0]
    else:
        md5 = None

    return md5


def send_shell_script(ip, os_version):
    """ This function generates a shell-script and sends it to the node.
        Then the script will be run in hohup."""

    repo_install = {
        'ubuntu':   "(grep -q \"updates\" /etc/apt/sources.list "
                    "|| echo -e \"\\ndeb http://{0}:8080/updates/ubuntu "
                    "precise main\" >> /etc/apt/sources.list)\n"
                    "apt-get update\n"
                    "apt-get upgrade -y\n".format(master_ip),

        'centos':   "yum-config-manager --add-repo=http://{0}:8080/updates/"
                    "centos/os/x86_64/\nyum update --skip-broken -y "
                    "--nogpgcheck\n".format(master_ip)
    }

    pkg_install_tool = {
        'ubuntu': '/usr/bin/dpkg -iE',
        'centos': '/bin/rpm -Uvh'
    }

    package_template = """
FILE="{0}"
FILEMD="{1}"
TOTAL_COUNT=`expr $TOTAL_COUNT + 1`

install_package $FILE $FILEMD
retval=$?
if [ $retval -eq 0 ]; then
    SUCCESS_COUNT=`expr $SUCCESS_COUNT + 1`
fi
"""
    package_text = ""
    try:
        for package in pkgs[os_version]:
            name = package.split("/")[-1]
            package_text += package_template.format(name, get_md5_from_file(
                                                    dest+name))
    except:
        msg = "{0} will be updated without custom packages".format(ip)
        print(msg)
        pass

    head_of_script = """#!/bin/bash
set -x
TMPDIR="/tmp"
TOTAL_COUNT=0
SUCCESS_COUNT=0
WGET=/usr/bin/wget
MD5="/usr/bin/md5sum"
INSTALL="%%install%%"
URL="http://%%master_ip%%:8080/updates/custom"
STATUS="/var/log/mos_apply_mu.status"
echo "STARTED" > $STATUS

%%repo_install%%
retval=$?

if [ $retval != 0 ]; then
    REPO_STATE="FAIL"
else
    REPO_STATE="OK"
fi
echo "PACKAGES_INSTALLING" >> $STATUS
install_package()
{
    OBJ=$1
    MD=$2
    $WGET -c -P $TMPDIR $URL/$OBJ
    retval=$?
    if [ $retval != 0 ]; then
        echo "$OBJ FAILED TO DOWNLOAD"
        return 1
    fi
    (echo "$MD  $TMPDIR/$OBJ" | $MD5 -c - --quiet)
    retval=$?
    if [ $retval != 0 ]; then
        echo "$OBJ CHECKSUM FAILED!"
        return 2
    fi
    $INSTALL $TMPDIR/$OBJ
    retval=$?
    if [ $retval != 0 ]; then
        echo "$OBJ FAILED TO INSTALL"
        return 3
    fi
    echo "$OBJ SUCCESS"
    return 0
}

%%packages_install%%

echo "REPO_UPD=$REPO_STATE;PKGS=$SUCCESS_COUNT\
of $TOTAL_COUNT INSTALLED" >> $STATUS

"""
    total = head_of_script\
        .replace("%%install%%", pkg_install_tool[os_version])\
        .replace("%%master_ip%%", master_ip)\
        .replace("%%packages_install%%", package_text)\
        .replace("%%repo_install%%", repo_install[os_version])

    if really:
        cmd = [
            "ssh",
            ip,
            "cat - > /root/mos_update.sh ; chmod +x /root/mos_update.sh; "
            "(nohup /root/mos_update.sh > /var/log/mos_apply_mu.log 2>&1) &"
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=None)
        print(proc.communicate(input=total))
        proc.wait()
        if proc.returncode == 0:
            print ("Script is running on {0}".format(ip))
            return True
        print ("Error during sending script to {0}".format(ip))
        return False
    else:
        return True

if __name__ == "__main__":
    arg_parse()

    ks = client.Client(
        username=username,
        password=password,
        tenant_name=tenant,
        auth_url=auth
    )
    token = ks.auth_token

    env_list = set()
    nodes = get_nodes()

    if (env_id > 0):
        env_list.add(env_id)
    else:
        get_operational_envs(nodes, env_list)

    print ("Environments to update: " + ",".join([str(x) for x in env_list]))
    do_node_update(nodes, env_list)
    sys.exit(0)
