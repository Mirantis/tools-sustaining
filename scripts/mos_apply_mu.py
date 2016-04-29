#!/usr/bin/env python
# Copyright 2015-2016 Mirantis, Inc.
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
import logging
import os
import subprocess
import sys
import time
import urllib2
import yaml

LOG = logging.getLogger("updater")
LOG.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter("%(message)s"))
ch.setLevel(logging.INFO)
LOG.addHandler(ch)

fh = logging.FileHandler("mos_apply_mu.log")
fh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
LOG.addHandler(fh)


class Config(object):
    def __init__(self):
        """
        :rtype: Config
        """
        self.cfg = {
            "username": "admin",
            "password": "admin",
            "tenant": "admin",
            "keystone": "http://127.0.0.1:5000/v2.0",
            "nailgun": "http://127.0.0.1:8000/",
            "mos_version": None,
            "mos_repos_to_install": set(["updates"]),
            "env_id": 0,
            "all_envs": False,
            "try_offline": False,
            "really": False,
            "check": False,
            "roles": None,
            "nodes": None,
            "interval": 0,
            "no_rsync": False,
            "use_latest": False,
            "ubuntu_pool": None,
            "apache_user": {
                'ubuntu': 'horizon',
                'centos': 'apache'
            },
            "apache_restart": {
                'ubuntu': 'service apache2 restart',
                'centos': 'service httpd restart'
            },
            "master_ip": None,
            "repo_install_text": 'echo "{REPO_TEXT}" > {REPO_FILE};\n',
            "repo_use_text": {
                'ubuntu':   'apt-get -o Dir::etc::sourcelist="-"'
                            ' -o Dir::Etc::sourceparts="/root/mos_update_repo/"'
                            ' -o APT::Get::List-Cleanup="0" update\n'
                            'apt-get -o Dir::etc::sourcelist="-"'
                            ' -o Dir::Etc::sourceparts="/root/mos_update_repo/"'
                            ' -o APT::Get::List-Cleanup="0"'
                            ' -o Dpkg::Options::="--force-confdef"'
                            ' -o Dpkg::Options::="--force-confold" -y'
                            ' --force-yes upgrade\n',
                'centos':   'yum --disablerepo="*" {REPOS_ACTIVATE} update'
                            ' --skip-broken -y --nogpgcheck\n'
            },
            "repo_activate": {
                "ubuntu": ' -o Dir::Etc::sourcelist="{REPO_FILE}" ',
                "centos": ' --enablerepo="mos-{REPO_NAME}" '
            }
        }
        for cmd in sys.argv[1:]:
            if '--env-id' in cmd:
                self.cfg['env_id'] = int(cmd.split('=')[1])
            if '--user' in cmd:
                self.cfg['username'] = cmd.split('=')[1]
            if '--pass' in cmd:
                self.cfg['password'] = cmd.split('=')[1]
            if '--tenant' in cmd:
                self.cfg['tenant'] = cmd.split('=')[1]
            if '--all-envs' in cmd:
                self.cfg['all_envs'] = True
            if '--offline' in cmd:
                self.cfg['try_offline'] = True
            if '--check' in cmd:
                self.cfg['check'] = True
            if '--update' in cmd:
                self.cfg['really'] = True
            if '--interval' in cmd:
                self.cfg['interval'] = int(cmd.split('=')[1])
            if '--roles' in cmd:
                t = cmd.split('=')[1]
                self.cfg['roles'] = [r.strip() for r in t.split(',')]
            if '--nodes' in cmd:
                t = cmd.split('=')[1]
                self.cfg['nodes'] = [r.strip() for r in t.split(',')]
                self.cfg['all_envs'] = True
            if '--fuel-ip' in cmd:
                fuel_ip = cmd.split('=')[1]
                self.cfg['keystone'] = 'http://' + fuel_ip + ':5000/v2.0'
                self.cfg['nailgun'] = 'http://' + fuel_ip + ':8000/'
            if '--master-ip' in cmd:
                self.cfg['master_ip'] = cmd.split('=')[1]
            if '--mos-version' in cmd:
                self.cfg['mos_version'] = cmd.split('=')[1]
            if '--mos-proposed' in cmd:
                self.cfg['mos_repos_to_install'].add("proposed")
            if '--mos-security' in cmd:
                self.cfg['mos_repos_to_install'].add("security")
            if '--use-latest' in cmd:
                self.cfg['use_latest'] = True
            if '--no-rsync' in cmd:
                self.cfg['no_rsync'] = True
            if '--version' in cmd:
                self.errexit(msg="VER_ID: 20022016", code=19)

        # validate all the data to find out incompatibles
        if (self.cfg['env_id'] > 0) and (self.cfg['all_envs']):
            self.errexit(
                msg="ERROR: You should only select either --env-id or --all-envs.",
                code=5
            )
        if (self.cfg['env_id'] == 0) and (not self.cfg['all_envs']):
            self.errexit(
                msg="ERROR: At least one option (env-id or all-envs) must be set.",
                code=6
            )
        if self.cfg['really'] and self.cfg['check']:
            self.errexit(
                msg="ERROR: You should use either --check or --update. Not both.",
                code=7
            )
        if not self.cfg['really'] and not self.cfg['check']:
            self.errexit(
                msg="ERROR: Either --check or --update must be set.",
                code=8
            )
        if self.cfg['master_ip'] is None:
            try:
                self.cfg['master_ip'] = self.guess_master_ip()
                LOG.info("\tMASTER_IP: {0}".format(self.cfg['master_ip']))
            except:
                self.errexit(
                    msg="ERROR: --master-ip is required! Set with --master-ip=X.X.X.X",
                    code=110
                )
        if self.cfg['mos_version'] is None:
            try:
                self.cfg['mos_version'] = self.guess_mos_version()
                LOG.info("\tMOS_VERSION: {0}".format(self.cfg['mos_version']))
            except:
                self.errexit(
                    msg="ERROR: MOS version is not determined, please set it with --mos-version",
                    code=111
                )

    def guess_mos_version(self):
        try:
            with open('/etc/fuel/version.yaml', 'r') as fp:
                return yaml.load(fp)['VERSION']['release']
        except:
            raise

    def guess_master_ip(self):
        try:
            with open('/etc/fuel/astute.yaml', 'r') as fp:
                return yaml.load(fp)['ADMIN_NETWORK']['ipaddress']
        except:
            raise

    def errexit(self, msg=None, code=1):
        usage = """
Tool to install maintenance updates to the nodes.
Usage:
    python mos_apply_mu.py {--env-id=N | --all-envs} {--check | --update}
                           [user=X] [--pass=Y] [--tenant=Z] [--offline]
                           [--master-ip=A.B.C.D] [--mos-version=E.F]

Required arguments:
  --env-id=N      ID of operational environment which needs to be updated
  --all-envs      Update all operational environments
  --update        Make real update (without this nothing will be updated)
  --check         Check status of selected nodes

Optional arguments:
  --offline      Add to update nodes which are currently offline in fuel
                 (may cause significant timeouts)
  --user         Username used in Fuel-Keystone authentication, default: admin
  --pass         Password suitable to username, default: admin
  --tenant       Suitable tenant, default: admin
  --mos-version  Version of MOS ('5.1.1', '6.1', '7.0', etc.)
                 default: taken from /etc/fuel/version.yaml
  --master-ip    IP-Address of Fuel-master node
                 default: taken from /etc/fuel/astute.yaml
  --roles        Comma-separated list of roles to update or check.
                 default: all roles are selected
  --nodes        Comma-separated list of nodes to update or check.
                 default: all nodes are selected
  --interval     Time gap in seconds between two consecutive nodes update.
                 Might be useful in big environments, to update an environment
                 more gently.
                 default: 0

Fuel 6.1 and higher options:
    By default only 'mos-updates' repository will
    be installed into an environment.

  --mos-proposed   Enable proposed updates repository
  --mos-security   Enable security updates repository
  --no-rsync       Don't download chosen repositories

Examples:

    python mos_apply_mu.py --env-id=11 --user=op --pass=V3ryS3Cur3 \
                           --update --master-ip="10.100.15.2"

      Runs update process on nodes in the environment #11

    python mos_apply_mu.py --env-id=11 --user=op --pass=V3ryS3Cur3 --check

      Checks the state of update process on the nodes in the environment #11
      States may be the following (separate for each node):
       * STARTED - script has been started and it's still working
       * REPO_UPD=OK - execution is over, maintenance update has been
         successfully installed.

    To get detailed log examine /var/log/mos_apply_mu.log on remote nodes.

Questions: dmeltsaykin@mirantis.com
Mirantis, 2015
"""
        print(usage)
        if msg:
            LOG.info(msg)
        sys.exit(code)

    def getcfg(self):
        return dict(self.cfg)


class BasicUpdater(object):
    def __init__(self, cfg):
        self.cfg = cfg

    def run(self):
        """
        main entry point for each subclass,
        returns nothing
        :return: None
        """
        # download repos if allowed
        if not self.cfg['no_rsync'] and self.cfg['really']:
            self.rsync()
        # get full list of nodes and envs from nailgun
        self.cfg['nodes_list'] = self.get_node_list()
        # decide either to update or to check
        if self.cfg['check']:
            self.check()
        else:
            self.update()

    def get_node_list(self):
        """
        Function to get list of nodes to update or to check
        if the update process was successful

        :return: set
        """
        def get_operational_envs(nodes):
            envs = set()
            for node in nodes:
                if self.cfg['try_offline'] and node['status'] == 'ready':
                    envs.add(node['cluster'])
                elif node['online'] and node['status'] == 'ready':
                    envs.add(node['cluster'])
            return envs

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
                    tenant=self.cfg['tenant'],
                    username=self.cfg['username'],
                    password=self.cfg['password']
                )
                req = urllib2.Request(self.cfg['keystone'] + '/tokens/')
                req.add_header('Content-Type', 'application/json')
                req.add_data(jrequest)
                out = json.load(urllib2.urlopen(req))
                return out['access']['token']['id']
            except:
                self.errexit(
                    msg="Cannot obtain token from keystone!",
                    code=95
                )
        req = urllib2.Request(self.cfg['nailgun'] + '/api/v1/nodes/')
        req.add_header('X-Auth-Token', keystone_get_token())
        nodes = json.load(urllib2.urlopen(req))
        # we fetched all the nodes from nailgun, here we must filter them out
        if self.cfg['env_id'] != 0:
            self.cfg['envs_list'] = set([self.cfg['env_id']])
        else:
            self.cfg['envs_list'] = get_operational_envs(nodes)
        return nodes

    def errexit(self, msg=None, code=1):
        LOG.info("Error occurred!")
        if msg:
            LOG.info(msg)
        sys.exit(code)

    def _run_helper(self, cmd, send_text=None, nostderr=True):
        """
        run command
        :param cmd: set[]
        :param nostderr: if True stderr redirected to /dev/null
        :return: tuple
        """

        devnull = open(os.devnull, 'w')
        if nostderr:
            STDERR = devnull
        else:
            STDERR = subprocess.PIPE
        STDOUT = subprocess.PIPE
        if send_text:
            STDIN = subprocess.PIPE
        else:
            STDIN = None
        LOG.debug("Started _run_helper() with: {0}".format(" ".join(cmd)))
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=STDIN,
                stderr=STDERR,
                stdout=STDOUT
            )
            result = ""
            if send_text:
                proc.communicate(input=send_text)
                proc.wait()
            while not send_text:
                out = proc.stdout.readline()
                if out == '' and proc.poll() is not None:
                    break
                result += out
            devnull.close()
            LOG.debug(result)
            return proc.returncode, result

        except Exception as e:
            LOG.debug("Exception in _run_helper()", exc_info=True)
            return 254, "Exception in _run_helper(): {0}".format(e.message)

    def _affected_nodes(self):
        """
        Returns a set of tuples(ip, os) of the selected nodes
        :return: set
        """
        def _is_selected(node):
            # These values are boolean
            e = node['cluster'] in self.cfg['envs_list']
            r = True if not self.cfg['roles'] else any(
                set(self.cfg['roles']).intersection(
                    set(node['roles'])))
            o = node['online'] or self.cfg['try_offline']
            n = True if not self.cfg['nodes'] else \
                node['ip'] in self.cfg['nodes']
            # Returns True if all conditions are met,
            # otherwise False is returned
            return all((e, r, o, n))

        return set((n['ip'], n['os_platform'])
                    for n in self.cfg['nodes_list'] if _is_selected(n))

    def check(self):
        """
        Checks what is the current state of nodes
        :return:
        """
        for ip, os in self._affected_nodes():
            cmd = ["ssh", ip, "tail -n1 /var/log/mos_apply_mu.status"]
            (state, msg) = self._run_helper(cmd=cmd)
            if state == 0:
                LOG.info("Node {0} state: {1}".format(ip, msg))
            else:
                LOG.info("Node {0}: no updates information found.".format(ip))

    def update(self):
        """
        does the real update of the selected nodes
        :return: None
        """
        update_script = """#!/bin/bash
exec > >(logger -tmos_apply_mu) 2>&1
set -x

STATUS="/var/log/mos_apply_mu.status"
echo "STARTED" > $STATUS

mkdir /root/mos_update_repo || rm /root/mos_update_repo/*

%%repo_install%%

retval=$?
if [ $retval != 0 ]; then
    REPO_STATE="FAIL"
else
    REPO_STATE="OK"
fi
if [ -a /usr/bin/modify-horizon-config.sh ]
then
    /usr/bin/modify-horizon-config.sh uninstall
    export HORIZON_CONFIG=/usr/share/openstack-dashboard/openstack_dashboard/settings.py
    export MURANO_SSL_ENABLED=False
    export USE_KEYSTONE_ENDPOINT=True
    export USE_SQLITE_BACKEND=False
    export APACHE_USER="%%apache_user%%"
    export APACHE_GROUP="%%apache_user%%"
    /usr/bin/modify-horizon-config.sh install
    /usr/share/openstack-dashboard/manage.py collectstatic --noinput
    %%apache_restart%%
else
    echo "Murano is not installed. Fix skipped."
fi

echo "UPDATE=$REPO_STATE" >> $STATUS
        """

        def _get_repo_install(os_version):
            """
            generates the text of repository installation
            :return: string
            """
            _result = ""
            _repos_activate = ""
            # making header per each repo
            for repo in self.cfg['mos_repos_to_install']:
                REPO_TEXT = self.cfg['repo_template'][os_version]['repo_text'].format(
                    MOS_VERSION=self.cfg['mos_version'],
                    MASTER_IP=self.cfg['master_ip'],
                    REPO_NAME=repo
                )
                REPO_FILE = self.cfg['repo_template'][os_version]['repo_file'].format(
                    REPO_NAME=repo
                )
                _result += self.cfg['repo_install_text'].format(
                    REPO_TEXT=REPO_TEXT,
                    REPO_FILE=REPO_FILE
                )
                _repos_activate += self.cfg['repo_activate'][os_version].format(
                    REPO_FILE=REPO_FILE,
                    REPO_NAME=repo
                )
            # this part adds yum update/apt-get upgrade
            _result += self.cfg['repo_use_text'][os_version].format(
                REPOS_ACTIVATE=_repos_activate
            )
            return _result

        for ip, distro in self._affected_nodes():
            script_text = update_script.replace(
                "%%repo_install%%",
                _get_repo_install(distro)
            ).replace(
                "%%apache_user%%",
                self.cfg['apache_user'][distro]
            ).replace(
                "%%apache_restart%%",
                self.cfg['apache_restart'][distro]
            )
            cmd = [
                "ssh", ip,
                "cat - > /root/mos_update.sh;chmod +x /root/mos_update.sh;"
                "(nohup /root/mos_update.sh > /dev/null 2>&1) &"
            ]

            state, out = self._run_helper(cmd=cmd, send_text=script_text)
            if state != 0:
                LOG.info("Node {0}: failure! [{1}:{2}]"
                         "Examine log at /var/log/remote/{0}/"
                         "mos_apply_mu.log".format(ip, state, out))
            else:
                LOG.info("Node {0}: started update. "
                         "Log at /var/log/remote/{0}/"
                         "mos_apply_mu.log".format(ip))
            LOG.info("Waiting {0} seconds.".format(self.cfg['interval']))
            time.sleep(self.cfg['interval'])

    def rsync(self):
        """
        downloads repositories to the fuel node
        :return:
        """
        def _dir_check_or_create(directory):
            """
            check whether dir exists, if not create it
            with all the subdirs
            :param directory:
            :return: None
            """
            try:
                os.makedirs(directory)
            except:
                pass

        for distro in ['ubuntu', 'centos']:
            for repo in self.cfg['mos_repos_to_install']:
                dest_dir = self.cfg['repo_template'][distro]["local_path"].format(
                    MOS_VERSION=self.cfg['mos_version'],
                    REPO_NAME=repo
                )
                rsync_url = self.cfg['repo_template'][distro]["rsync"].format(
                    MOS_VERSION=self.cfg['mos_version'],
                    REPO_NAME=repo
                )
                _dir_check_or_create(dest_dir)
                cmd = ["rsync", "-vap", "--chmod=Dugo+x", rsync_url, dest_dir]
                LOG.info("RSYNC: Downloading {0} repository for {1}".format(
                    repo, distro))
                retval, text = self._run_helper(cmd=cmd)
                if retval != 0:
                    self.errexit("RSYNC: Error downloading repository! [{0}:{1}]".format(
                        retval, text))

        if self.cfg['ubuntu_pool']:
            LOG.info("RSYNC: Additional pool is downloading.")
            _dir_check_or_create(self.cfg['ubuntu_pool']['local_path'])
            cmd = ["rsync", "-vap", "--chmod=Dugo+x",
                self.cfg['ubuntu_pool']['rsync'], self.cfg['ubuntu_pool']['local_path']]
            retval, text = self._run_helper(cmd=cmd)
            if retval != 0:
                self.errexit("RSYNC: Error downloading pool! [{0}:{1}]".format(
                    retval, text))

    def rsync_pool_if_needed(self):
        pass


class Updater511(BasicUpdater):
    def __init__(self, cfg):
        super(self.__class__, self).__init__(cfg)
        # we have only updates repository for 5.1.1
        # regardless what was selected by the user
        self.cfg['mos_repos_to_install'] = set(['updates'])
        self.cfg['repo_template'] = {
            "ubuntu": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/"
                    "mirror/fwm/{MOS_VERSION}/{REPO_NAME}/ubuntu/",
                "local_path":
                    "/var/www/nailgun/{REPO_NAME}/ubuntu/",
                "repo_file":
                    "/root/mos_update_repo/mos-{REPO_NAME}.list",
                "repo_text":
                    "deb http://{MASTER_IP}:8080/updates/ubuntu "
                    "precise main restricted",
                "prio": "1150"
            },
            "centos": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/"
                    "mirror/fwm/{MOS_VERSION}/{REPO_NAME}/centos/",
                "local_path":
                    "/var/www/nailgun/{REPO_NAME}/centos/",
                "repo_text":
                    "[mos-{REPO_NAME}]\n"
                    "name=mos-{REPO_NAME}\n"
                    "baseurl=http://{MASTER_IP}:8080/updates/centos/"
                    "os/x86_64/\ngpgcheck=0\n",
                "repo_file":
                    "/etc/yum.repos.d/mos-{REPO_NAME}.repo",
                "prio": "100"
            }
        }
        self.cfg["repo_use_text"] = {
                'ubuntu':   'apt-get -o Dir::etc::sourcelist="-"'
                            ' -o Dir::Etc::sourceparts="/root/mos_update_repo/"'
                            ' -o APT::Get::List-Cleanup="0" update\n'
                            'apt-get -o Dir::etc::sourcelist="-"'
                            ' -o Dir::Etc::sourceparts="/root/mos_update_repo/"'
                            ' -o APT::Get::List-Cleanup="0"'
                            ' -o Dpkg::Options::="--force-confdef"'
                            ' -o Dpkg::Options::="--force-confold" -y'
                            ' --force-yes dist-upgrade\n',
                'centos':   'yum --disablerepo="*" {REPOS_ACTIVATE} update'
                            ' --skip-broken -y --nogpgcheck\n'
        }


class Updater60(BasicUpdater):
    def __init__(self, cfg):
        super(self.__class__, self).__init__(cfg)
        # we have only updates repository for 6.0
        # regardless what was selected by the user
        self.cfg['mos_repos_to_install'] = set(['updates'])
        self.cfg['repo_template'] = {
            "ubuntu": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/"
                    "mirror/fwm/{MOS_VERSION}/{REPO_NAME}/ubuntu/",
                "local_path":
                    "/var/www/nailgun/{REPO_NAME}/ubuntu/",
                "repo_file":
                    "/root/mos_update_repo/mos-{REPO_NAME}.list",
                "repo_text":
                    "deb http://{MASTER_IP}:8080/updates/ubuntu "
                    "precise main restricted",
                "prio": "1150"
            },
            "centos": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/"
                    "mirror/fwm/{MOS_VERSION}/{REPO_NAME}/centos/",
                "local_path":
                    "/var/www/nailgun/{REPO_NAME}/centos/",
                "repo_text":
                    "[mos-{REPO_NAME}]\n"
                    "name=mos-{REPO_NAME}\n"
                    "baseurl=http://{MASTER_IP}:8080/updates/centos/"
                    "os/x86_64/\ngpgcheck=0\n",
                "repo_file":
                    "/etc/yum.repos.d/mos-{REPO_NAME}.repo",
                "prio": "100"
            }
        }


class Updater61(BasicUpdater):
    def __init__(self, cfg):
        super(self.__class__, self).__init__(cfg)
        self.cfg['repo_template'] = {
            "ubuntu": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/"
                    "mirror/mos/ubuntu/dists/mos{MOS_VERSION}-{REPO_NAME}/",
                "local_path":
                    "/var/www/nailgun/mos-ubuntu/dists/mos{MOS_VERSION}-{REPO_NAME}/",
                "repo_file":
                    "/root/mos_update_repo/mos-{REPO_NAME}.list",
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
        self.cfg['ubuntu_pool'] = {
            'rsync': "rsync://mirror.fuel-infra.org"
                     "/mirror/mos/ubuntu/pool/",
            'local_path': "/var/www/nailgun/mos-ubuntu/pool/"
        }


class Updater70(BasicUpdater):
    def __init__(self, cfg):
        super(self.__class__, self).__init__(cfg)
        self.cfg['repo_template'] = {
            "ubuntu": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/"
                    "mirror/mos-repos/ubuntu/{MOS_VERSION}/dists/mos{MOS_VERSION}-{REPO_NAME}/",
                "local_path":
                    "/var/www/nailgun/mos-ubuntu/dists/mos{MOS_VERSION}-{REPO_NAME}/",
                "repo_file":
                    "/root/mos_update_repo/mos-{REPO_NAME}.list",
                "repo_text":
                    "deb http://{MASTER_IP}:8080/mos-ubuntu "
                    "mos{MOS_VERSION}-{REPO_NAME} main restricted",
                "prio": "1150"
            },
            "centos": {
                "rsync":
                    "rsync://mirror.fuel-infra.org/mirror/"
                    "mos-repos/centos/mos{MOS_VERSION}-centos6-fuel/{REPO_NAME}/",
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
        self.cfg['ubuntu_pool'] = {
            'rsync': "rsync://mirror.fuel-infra.org"
                     "/mirror/mos-repos/ubuntu/7.0/pool/",
            'local_path': "/var/www/nailgun/mos-ubuntu/pool/"
        }


if __name__ == "__main__":
    v = {
        "5.1.1": Updater511,
        "6.0": Updater60,
        "6.1": Updater61,
        "7.0": Updater70
    }
    config = Config()
    ver = v.get(config.cfg['mos_version'], None)
    if ver:
        inst = ver(config.getcfg())
        inst.run()
    else:
        LOG.info("This script is not designed to update Fuel {0}".format(
            config.cfg['mos_version']))
