#!/usr/bin/env python
# Copyright 2015 Mirantis, Inc.
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
import os
import subprocess
import sys
import urllib2
import yaml


username = 'admin'
password = 'admin'
tenant = 'admin'
keystone = 'http://127.0.0.1:5000/v2.0'
nailgun = 'http://127.0.0.1:8000/'
logfile = 'mos_apply_mu.log'
mos_version = None
mos_repos_to_install = set(["updates"])
new_fuel = ['6.1', '7.0', '8.0']

env_id = 0
all_envs = False
try_offline = False
really = False
check = False
no_rsync = False
use_latest = False

master_ip = None
path = "custom.pkg"
install_custom = False
pkgs = None
dest = "/var/www/nailgun/updates/custom/"

mos_repo_template = {
    "ubuntu": {
        "rsync":
            "rsync://mirror.fuel-infra.org/"
            "mirror/mos/ubuntu/dists/mos{MOS_VERSION}-{REPO_NAME}/",
        "local_path":
            "/var/www/nailgun/mos-ubuntu/dists/mos{MOS_VERSION}-{REPO_NAME}/",
        "repo_file":
            "/etc/apt/sources.list.d/mos-{REPO_NAME}.list",
        "repo_text":
            "deb http://{MASTER_IP}:8080/mos-ubuntu "
            "mos{MOS_VERSION}-{REPO_NAME} main restricted",
        "prio": "1150"
    },
    "centos": {
        "rsync":
            "rsync://mirror.fuel-infra.org/mirror/"
            "mos/centos-6/mos{MOS_VERSION}/{REPO_NAME}/",
        "local_path":
            "/var/www/nailgun/mos-centos/mos{MOS_VERSION}/{REPO_NAME}",
        "repo_text":
            "[mos-{REPO_NAME}]\n"
            "name=mos-{REPO_NAME}\n"
            "baseurl=http://{MASTER_IP}:8080/mos-centos/mos{MOS_VERSION}/"
            "{REPO_NAME}/\ngpgcheck=0\n",
        "repo_file":
            "/etc/yum.repos.d/mos-{REPO_NAME}.repo",
        "prio": "100"
        }
}

latest_mos_repo_template = {
    "ubuntu": {
        "rsync": "rsync://mirror.fuel-infra.org/mirror/mos/snapshots/"
                 "ubuntu-latest/dists/mos{MOS_VERSION}-{REPO_NAME}/",
        "local_path": "/var/www/nailgun/mos-ubuntu/dists/"
                      "latest-mos{MOS_VERSION}-{REPO_NAME}/",
        "repo_file": "/etc/apt/sources.list.d/latest-mos-{REPO_NAME}.list",
        "repo_text": "deb http://{MASTER_IP}:8080/mos-ubuntu latest"
                     "-mos{MOS_VERSION}-{REPO_NAME} main restricted",
        "prio": "1150"
    },
    "centos": {
        "rsync":
            "rsync://mirror.fuel-infra.org/mirror/mos/snapshots/"
            "centos-6-latest/mos{MOS_VERSION}/{REPO_NAME}/",
        "local_path":
            "/var/www/nailgun/mos-centos/mos{MOS_VERSION}/latest-{REPO_NAME}",
        "repo_text":
            "[latest-mos-{REPO_NAME}]\n"
            "name=latest-mos-{REPO_NAME}\n"
            "baseurl=http://{MASTER_IP}:8080/mos-centos/"
            "mos{MOS_VERSION}/latest-{REPO_NAME}/\ngpgcheck=0\n",
        "repo_file":
            "/etc/yum.repos.d/latest-mos-{REPO_NAME}.repo",
        "prio": "100"
        }
}


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
    global mos_version
    global keystone
    global nailgun
    global use_latest
    global no_rsync

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
    --mos-version       Version of MOS ('old', '6.1', '7.0', etc.)
                            default: taken from /etc/fuel/version.yaml
    --master-ip         IP-Address of Fuel-master node
                            default: taken from /etc/fuel/astute.yaml

Fuel 6.1 and higher options:

        By default only 'mos-updates' repository will
        be installed into an environment.

    --mos-proposed      Enable proposed updates repository
    --mos-security      Enable security updates repository
    --no-rsync          Don't download chosen repositories

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
        REPO_UPD=OK;CUSTOM=0 of 2 INSTALLED - execution is over,
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
        if '--fuel-ip' in cmd:
            fuel_ip = cmd.split('=')[1]
            keystone = 'http://' + fuel_ip + ':5000/v2.0'
            nailgun = 'http://' + fuel_ip + ':8000/'
        if '--file' in cmd:
            path = cmd.split('=')[1]
        if '--with-custom' in cmd:
            install_custom = True
        if '--master-ip' in cmd:
            master_ip = cmd.split('=')[1]
        if '--mos-version' in cmd:
            mos_version = cmd.split('=')[1]
        if '--mos-proposed' in cmd:
            mos_repos_to_install.add("proposed")
        if '--mos-security' in cmd:
            mos_repos_to_install.add("security")
        if '--use-latest' in cmd:
            use_latest = True
        if '--no-rsync' in cmd:
            no_rsync = True
        if '--version' in cmd:
            print ("VER_ID: 22092015")
            sys.exit(19)

    if (env_id > 0) and (all_envs):
        print (usage)
        print ("ERROR: You should only select either --env-id or --all-envs.")
        sys.exit(5)
    if (env_id == 0) and (not all_envs):
        print (usage)
        print ("ERROR: At least one option (env-id or all-envs) must be set.")
        sys.exit(6)
    if really and check:
        print (usage)
        print ("ERROR: You should use either --check or --update. Not both.")
        sys.exit(7)
    if not really and not check:
        print (usage)
        print ("ERROR: Either --check or --update must be set.")
        sys.exit(8)
    if master_ip is None:
        try:
            master_ip = guess_master_ip()
            print ("\tMASTER_IP: {0}".format(master_ip))
        except:
            print (usage)
            print (
                "ERROR: --master-ip is required! Set with --master-ip=X.X.X.X"
            )
            sys.exit(110)
    if mos_version is None:
        try:
            mos_version = guess_mos_version()
            print ("\tMOS_VERSION: {0}".format(mos_version))
        except:
            print ("MOS Version cannot be detected, setting to 'old'")
            mos_version = 'old'


def guess_mos_version():
    try:
        with open('/etc/fuel/version.yaml', 'r') as fp:
            ver = yaml.load(fp)['VERSION']['release']
            if ver not in new_fuel:
                return 'old'
            return ver
    except:
        raise


def guess_master_ip():
    try:
        with open('/etc/fuel/astute.yaml', 'r') as fp:
            return yaml.load(fp)['ADMIN_NETWORK']['ipaddress']
    except:
        raise


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
    # check if dst dir exists if not create it (and others)
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
    req = urllib2.Request(nailgun + '/api/v1/nodes/')
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
        print("Node {0}: no updates information found.".format(ip))
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
    if pkgs is not None:
        print ("Custom packages will be installed")
    else:
        print("No custom packages will be installed")

    if really:
        if packages_to_install is not None:
            packages_download()
        else:
            print ("Unable to get packages list from file {0}".format(path))

    for ip, os_version in to_update:
        print ("{0}'s log: /var/log/remote/"
               "{0}/mos_apply_mu.log".format(ip))
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
        Then the script will be run in nohup."""

    repo_install = {
        'ubuntu':   "(grep -q \"updates\" /etc/apt/sources.list "
                    "|| echo -e \"\\ndeb http://{0}:8080/updates/ubuntu "
                    "precise main\" >> /etc/apt/sources.list)\n"
                    "apt-get update\n"
                    "apt-get -o Dpkg::Options::=\"--force-confdef\" -o "
                    "Dpkg::Options::=\"--force-confold\" -y "
                    "upgrade\n".format(master_ip),

        'centos':   "yum-config-manager --add-repo=http://{0}:8080/updates/"
                    "centos/os/x86_64/\nyum update --skip-broken -y "
                    "--nogpgcheck\n".format(master_ip)
    }

    pkg_mgr_string = {
        'ubuntu':   'apt-get {repos} -o Dir::Etc::sourceparts="-"'
                    ' -o APT::Get::List-Cleanup="0" update\n'
                    'apt-get {repos} -o Dir::Etc::sourceparts="-"'
                    ' -o APT::Get::List-Cleanup="0"'
                    ' -o Dpkg::Options::="--force-confdef"'
                    ' -o Dpkg::Options::="--force-confold" -y upgrade\n',
        'centos':   'yum --disablerepo="*" {repos} update'
                    ' --skip-broken -y --nogpgcheck\n'
    }

    if mos_version != 'old':
        repo_string = ""
        tmpl = ''
        for repo in mos_repos_to_install:
            if os_version == "ubuntu":
                repo_string += ' -o Dir::Etc::sourcelist="{repo_file}"'.format(
                    repo_file=mos_repo_template[os_version]['repo_file'].format(
                        REPO_NAME=repo))
            else:
                repo_string += ' --enablerepo="mos-{repo_name}"'.format(
                    repo_name=repo)

            tmpl += 'echo "{repo_text}" > {repo_file};\n'.format(
                repo_text=mos_repo_template[os_version]['repo_text'].format(
                    MASTER_IP=master_ip,
                    MOS_VERSION=mos_version,
                    REPO_NAME=repo
                ),
                repo_file=mos_repo_template[os_version]['repo_file'].format(
                        REPO_NAME=repo
                )
            )
        if use_latest:
            for repo in mos_repos_to_install:
                if os_version == "ubuntu":
                    repo_string += ' -o Dir::Etc::sourcelist="{repo_file}"'.format(
                        repo_file=latest_mos_repo_template[os_version]['repo_file'].format(
                            REPO_NAME=repo))
                else:
                    repo_string += ' --enablerepo="latest-mos-{repo_name}"'.format(
                        repo_name=repo)

                tmpl += 'echo "{repo_text}" > {repo_file};\n'.format(
                    repo_text=latest_mos_repo_template[os_version]['repo_text'].format(
                        MASTER_IP=master_ip,
                        MOS_VERSION=mos_version,
                        REPO_NAME=repo
                    ),
                    repo_file=latest_mos_repo_template[os_version]['repo_file'].format(
                            REPO_NAME=repo
                    )
                )
        tmpl += pkg_mgr_string[os_version].format(repos=repo_string)

        repo_install = {
            os_version: tmpl
        }

    pkg_install_tool = {
        'ubuntu': '/usr/bin/dpkg -iE',
        'centos': '/bin/rpm -Uvh'
    }

    apache_user = {
        'ubuntu': 'horizon',
        'centos': 'apache'
    }

    apache_restart = {
        'ubuntu': 'service apache2 restart',
        'centos': 'service httpd restart'
    }

    murano_fix = """
if [ -a /usr/bin/modify-horizon-config.sh ]
then
    /usr/bin/modify-horizon-config.sh uninstall
    export HORIZON_CONFIG=/usr/share/openstack-dashboard/openstack_dashboard/settings.py
    export MURANO_SSL_ENABLED=False
    export USE_KEYSTONE_ENDPOINT=True
    export USE_SQLITE_BACKEND=False
    export APACHE_USER="{apache_user}"
    export APACHE_GROUP="{apache_user}"
    /usr/bin/modify-horizon-config.sh install
    /usr/share/openstack-dashboard/manage.py collectstatic --noinput
    {apache_restart}
else
    echo "Murano is not installed. Fix skipped."
fi
    """.format(
        apache_user=apache_user[os_version],
        apache_restart=apache_restart[os_version]
    )

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
        pass

    head_of_script = """#!/bin/bash
exec > >(logger -tmos_apply_mu) 2>&1

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

%%murano_fix%%

echo "REPO_UPD=$REPO_STATE;CUSTOM=$SUCCESS_COUNT of $TOTAL_COUNT INSTALLED" >> $STATUS

"""
    total = head_of_script\
        .replace("%%install%%", pkg_install_tool[os_version])\
        .replace("%%master_ip%%", master_ip)\
        .replace("%%packages_install%%", package_text)\
        .replace("%%repo_install%%", repo_install[os_version])\
        .replace("%%murano_fix%%", murano_fix)

    if really:
        cmd = [
            "ssh",
            ip,
            "cat - > /root/mos_update.sh ; chmod +x /root/mos_update.sh; "
            "(nohup /root/mos_update.sh > /dev/null 2>&1) &"
        ]
        with open(os.devnull, 'w') as DNULL:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=DNULL)
        proc.communicate(input=total)
        proc.wait()
        if proc.returncode == 0:
            print ("Script is running on {0}".format(ip))
            return True
        print ("Error during sending script to {0}".format(ip))
        return False
    else:
        return True


def keystone_get_token():
    try:
        jrequest = """
        {{
            "auth": {{
                "tenantName": "{tenant}",
                "passwordCredentials": {{
                    "username": "{username}",
                    "password": "{password}"
                }}
            }}
        }}
        """.format(
            tenant=tenant,
            username=username,
            password=password
        )
        req = urllib2.Request(keystone + '/tokens/')
        req.add_header('Content-Type', 'application/json')
        req.add_data(jrequest)
        out = json.load(urllib2.urlopen(req))
        return out['access']['token']['id']
    except:
        return None


def rsync_repos():
    if not really or no_rsync:
        print ("Download of repository is skipped")
        return None
    # work around the mos-ubuntu repos
    # that have no individual pools
    try:
        os.makedirs("/var/www/nailgun/mos-ubuntu/pool")
    except:
        pass
    cmdline = "rsync -vap --chmod=Dugo+x "\
              "rsync://mirror.fuel-infra.org/mirror/mos/ubuntu/pool/ "\
              "/var/www/nailgun/mos-ubuntu/pool/;"
    if use_latest:
        cmdline += "rsync -vap --chmod=Dugo+x "\
              "rsync://mirror.fuel-infra.org/mirror/mos/snapshots/ubuntu-latest/pool/ "\
              "/var/www/nailgun/mos-ubuntu/pool/;"
    for distro in ['ubuntu', 'centos']:
        for repo in mos_repos_to_install:
            try:
                os.makedirs(mos_repo_template[distro]['local_path'].format(
                        MOS_VERSION=mos_version,
                        REPO_NAME=repo
                    )
                )
                if use_latest:
                    os.makedirs(latest_mos_repo_template[distro]['local_path'].format(
                        MOS_VERSION=mos_version,
                        REPO_NAME=repo
                    )
                )
            except:
                pass
            cmdline += 'rsync -vap --chmod=Dugo+x {url} {folder};'.format(
                url=mos_repo_template[distro]['rsync'].format(
                    MOS_VERSION=mos_version,
                    REPO_NAME=repo
                ),
                folder=mos_repo_template[distro]['local_path'].format(
                    MOS_VERSION=mos_version,
                    REPO_NAME=repo
                )
            )
            if use_latest:
                cmdline += 'rsync -vap --chmod=Dugo+x {url} {folder};'.format(
                url=latest_mos_repo_template[distro]['rsync'].format(
                    MOS_VERSION=mos_version,
                    REPO_NAME=repo
                ),
                folder=latest_mos_repo_template[distro]['local_path'].format(
                    MOS_VERSION=mos_version,
                    REPO_NAME=repo
                )
            )
    print (cmdline)
    retval = os.system(cmdline)
    if retval != 0:
        print ("Error during rsync!")
        sys.exit(21)


if __name__ == "__main__":

    arg_parse()

    token = keystone_get_token()

    env_list = set()
    nodes = get_nodes()

    if (env_id > 0):
        env_list.add(env_id)
    else:
        get_operational_envs(nodes, env_list)
    if mos_version == 'old':
        print ("Environments to update: " + ",".join(
            [str(x) for x in env_list]))
        do_node_update(nodes, env_list)
    else:
        rsync_repos()
        print ("Selected repositories: {0}".format(
            ",".join(mos_repos_to_install)))
        do_node_update(nodes, env_list)
    sys.exit(0)
