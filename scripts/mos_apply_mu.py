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
    print ("Can't find keystone-client, this script must be only used on Fuel-node")
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

master_ip = "10.20.0.2"

path = "custom.pkg"
install_custom = False
pkgs = None
dest = "/var/www/nailgun/updates/custom/"


def arg_parse ():
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

    usage="""
Tool to install updates repository into running cluster nodes.
Usage:
    python nodes_update.py [--env-id=X] [--all-envs]

Params:
    --master-ip         IP-Address of Fuel-master node
                            default: 10.20.0.2
    --env-id            ID of operational environment
                            which needs to be updated
    --all-envs          Update all operational environments
    --offline           Try to update nodes which are currently offline in fuel
                            (can cause significant timeouts)
    --update            Make real update (without this nothing will be updated)
    --user              Username used in Fuel-Keystone authentication
                            default: admin
    --pass              Password suitable to username
                            default: admin
    --tenant            Suitable tenant
                            default: admin
    --with-custom       Download and install custom packages from json-file
                            default filename: custom.pkg

    --file              Name of the config file in json-format with list of
                        custom packages to download and install


Examples:

    python nodes_update.py --all-envs --user=op --pass=V3ryS3Cur3 --master-ip="10.100.15.2"
    Inspects Fuel with op's credentials and shows commands that should be applied

    python nodes_update.py --all-envs --user=op --pass=V3ryS3Cur3 --update --master-ip="10.100.15.2"
    Makes real update

Log is stored in mos_apply_mu.log please read it carefully.

Questions: dmeltsaykin@mirantis.com

Mirantis, 2015
"""

    for cmd in sys.argv[1:]:
        if '--env-id' in cmd: env_id = int(cmd.split('=')[1])
        if '--user' in cmd: username = cmd.split('=')[1]
        if '--pass' in cmd: password = cmd.split('=')[1]
        if '--tenant' in cmd: tenant = cmd.split('=')[1]
        if '--all-envs' in cmd: all_envs = True
        if '--offline' in cmd: try_offline = True
        if '--update' in cmd: really = True
        if '--file' in cmd: path = cmd.split('=')[1]
        if '--with-custom' in cmd: install_custom = True
        if '--master-ip' in cmd: master_ip = cmd.split('=')[1]

    if (env_id > 0) and (all_envs == True):
        print ("You should only select either --env-id or --all-envs.")
        print (usage)
        sys.exit(5)
    if (env_id == 0) and (all_envs == False):
        print ("At least one option (env-id or all-envs) must be set.")
        print (usage)
        sys.exit(6)

    repo_install = {
        'ubuntu': """(grep -q "updates" /etc/apt/sources.list || echo -e "\ndeb http://{0}:8080/updates/ubuntu precise main" >> /etc/apt/sources.list); apt-get update; apt-get upgrade -y""".format(master_ip),
        'centos': """yum-config-manager --add-repo=http://{0}:8080/updates/centos/os/x86_64/; yum update --skip-broken -y --nogpgcheck""".format(master_ip)
    }


def get_downloads_list():
    global pkgs
    try:
        file=open(path,'r')
        pkgs=json.load(file)
        file.close()
    except:
        return None
    return True

def packages_download ():
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
            cmd="wget -c -P{0} \"{1}\"".format(dest, t)
            print ("Running: {0}".format(cmd))
            retval += os.system(cmd)

    if retval != 0:
        print ("Some downloads are failed!")
    return (retval)

def get_nodes ():
    req = urllib2.Request('http://127.0.0.1:8000/api/v1/nodes/')
    req.add_header('X-Auth-Token',token)
    nodes = json.load(urllib2.urlopen(req))
    return nodes

def get_operational_envs (nodes, env_list):
    for node in nodes:
        if (node['status'] == "ready"):
            if try_offline == True: env_list.add(node['cluster'])
            elif node['online'] == True: env_list.add(node['cluster'])

def do_node_update (nodes, env_list):
    to_update = set()
    for env in env_list:
        for node in nodes:
            if node['cluster'] == env:
                if try_offline == True:
                    to_update.add((node['ip'], node['os_platform']))
                elif node['online'] == True:
                    to_update.add((node['ip'], node['os_platform']))

    if install_custom == True:
        if get_downloads_list() is not None:
            packages_download()
        else:
            print ("Unable to get packages list from file {0}".format(path))

    print (to_update)
    if really == True:
        log = open(logfile, 'w',0)
    else:
        log = open('/dev/null', 'w')

    should = len(to_update)
    have = 0
    for ip,os_version in to_update:
        log.write("-------------- UPDATING {0} -----------------\n".format(ip))
        cmdline = ["ssh", "-t", "-t", str(ip), repo_install[os_version]]
        print (cmdline)
        log.write(str(cmdline)+"\n")
        if really == True:
            tmp=subprocess.Popen(cmdline, stdin=None, stdout=log, stderr=log)
            tmp.wait()
            if tmp.returncode != 0:
                msg="Update procedure on {0} returned FAIL({1}). Check log for details.\n".format(ip,tmp.returncode)
            else:
                msg="Update procedure on {0} completed with success!\n".format(ip)
                have += 1
            print(msg)
            log.write(msg)
        if install_custom == True:
            do_install_custom(ip, os_version, flag=really, logfp=log)
        log.write("---------------- DONE -------------------\n")
    msg = "Total: {0} out of {1} nodes updated successfully.\n".format(have, should)
    print (msg)
    log.write(msg)
    log.flush()
    log.close()

def do_install_custom (ip, os_version, flag=False, logfp=None):
    install={"ubuntu": "/usr/bin/dpkg -i ", "centos": "rpm -Uvh "}
    if pkgs is None: return (None)

    for package in pkgs[os_version]:
        cmdline=["scp", dest+package.split("/")[-1], str(ip)+":/tmp/"]
        print (cmdline)
        if flag == True:
            tmp = subprocess.Popen(cmdline, stdin=None, stdout=logfp, stderr=logfp)
            tmp.wait()
            if tmp.returncode != 0:
                msg = "Error in copying {0} to {1}. Installation skipped. See log for information\n".format(
                                                                                package.split("/")[-1], ip)
                print (msg)
                logfp.write (msg)
                continue
            else:
                msg = "Copied {0} to {1}\n".format(package.split("/")[-1], ip)
                print (msg)
                logfp.write (msg)

        cmdline=["ssh","-t", "-t", str(ip), "{0}".format(install[os_version]+"/tmp/"+package.split("/")[-1])]
        print (cmdline)
        if flag == True:
            tmp = subprocess.Popen(cmdline, stdin=None, stdout=logfp, stderr=logfp)
            tmp.wait()
            if tmp.returncode != 0:
                msg = "Installation {0} on {1} returned FAIL. Please check log.\n".format(
                                                                    package.split("/")[-1],ip)
            else:
                msg = "Installation {0} on {1} completed with success!.\n".format(
                                                                    package.split("/")[-1],ip)
            print (msg)
            logfp.write(msg)

if __name__ == "__main__":
    arg_parse()

    ks = client.Client (username=username, password=password,
            tenant_name=tenant, auth_url=auth)
    token = ks.auth_token

    env_list = set()
    nodes = get_nodes()

    if (env_id > 0):
        env_list.add(env_id)
    else:
        get_operational_envs(nodes,env_list)

    print ("Following envs will be updated: " + ",".join([str(x) for x in env_list]))
    do_node_update(nodes, env_list)
    sys.exit(0)
