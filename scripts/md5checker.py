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
import textwrap

components = [
    "nova",
    "novaclient",
    "neutron",
    "neutronclient",
    "cinder",
    "cinderclient",
    "glance",
    "glanceclient",
    "glance_store",
    "swift",
    "swift3",
    "swiftclient",
    "heat",
    "heatclient",
    "horizon",
    "oslo",
    "murano",
    "muranoapi",
    "muranoclient",
    "muranodashboard",
    "sahara",
    "ceilometerclient",
    "ceilometer",
    "saharaclient",
    "keystone",
    "keystonemiddleware",
    "keystoneclient"
]

def usage(err=None):
    print("""
MOS release consistency checker.
Options
====
    --check        Do the check
    --release      Set Fuel release
    --filename     Set name of file to use as a database
    --os           Set os version (centos/ubuntu)
    --user         Username to use in keystone
    --pass         Password to use in keystone
    --tenant       Tenant to use in keystone
    --env-id       Environment ID to check
    --all-envs     Check all environments
    --verbose      Print corrupted/missing file names

Usage
=====
    Checking consistency of MOS assuming that it is Fuel 6.0 release
    and keystone credentials are `admin`:`s3kr3tp@ss` from tenant `admin`
    python md5checker.py --release=6.0 --os=ubuntu --check \\
                         --tenant=admin --user=admin --pass=s3kr3tp@ss
    """)
    if err:
        print ("\nError: " + err)
    sys.exit(1)

def opts_parse():
    # setting up defaults
    cfg = {
        "version": "0.1",
        "release": None,
        "os": "ubuntu",
        "username" : "admin",
        "password": "admin",
        "tenant": "admin",
        "path": {
            "ubuntu": "/usr/lib/python2.7/dist-packages",
            "centos": "/usr/lib/python2.6/site-packages"
        },
        "filename": "md5checker.dat",
        "env": 1,
        "all_envs": False,
        "action": "check",
        "verbose": False
    }
    if len(sys.argv) < 2:
        usage("At least --release must be set!")
    for opt in sys.argv:
        if '--gather' in opt:
            cfg['action'] = 'gather'
        if '--release' in opt:
            cfg['release'] = opt.split("=")[1]
        if '--os' in opt:
            cfg['os'] = opt.split("=")[1]
        if '--filename' in opt:
            cfg['filename'] = opt.split("=")[1]
        if '--user' in opt:
            cfg['username'] = opt.split("=")[1]
        if '--pass' in opt:
            cfg['password'] = opt.split("=")[1]
        if '--tenant' in opt:
            cfg['tenant'] = opt.split("=")[1]
        if '--env' in opt:
            cfg['env'] = int(opt.split("=")[1])
        if '--all-envs' in opt:
            cfg['all_envs'] = True
        if '--verbose' in opt:
            cfg['verbose'] = True

    return cfg



class Gatherer(object):
    def __init__(self, cfg):
        self.cfg = dict(cfg)
        try:
            with open(self.cfg['filename'], 'r') as fp:
                self.cfg['data'] = json.load(fp)
        except:
            self.cfg['data'] = self._prepare_structure()
        if self.cfg['release'] is None:
            usage("--release must be set!")
        if self.cfg['release'] not in self.cfg['data'].keys():
            self.cfg['data'][self.cfg['release']] = dict()

    def _prepare_structure(self):
        data = dict()
        data[self.cfg['release']] = dict()
        return data

    def _gather(self, remote=None):
        if remote:
            os_version = remote[1]
            data = dict()
            fdir = " ".join(self.cfg['path'][os_version] + "/" + l for l in components)
            cmd = ["ssh {1} \"/usr/bin/find {0} -name '*.py' -exec 'md5sum' '{{}}' ';'\"".format(fdir, remote[0])]
        else:
            os_version = self.cfg['os']
            data = self.cfg['data'][self.cfg['release']]
            fdir = " ".join(self.cfg['path'][os_version] + "/" + l for l in components)
            cmd = ["/usr/bin/find {0} -name \'*.py\' -exec \'md5sum\' \'{{}}\' \';\'".format(fdir)]
        run = subprocess.Popen(
            cmd,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=None,
            shell=True
        )
        while True:
            out = run.stdout.readline()
            if out == '' and run.poll() is not None:
                break
            if out:
                tmp = out.split("  ")
                md5 = tmp[0]
                comp_tmp = tmp[1].strip().replace(
                    self.cfg['path'][os_version] + "/",
                    ''
                )
                pos = comp_tmp.find("/")
                comp = comp_tmp[0:pos]
                fl = comp_tmp[pos+1:]
                try:
                    data[comp][fl] = md5
                except KeyError:
                    data.update({comp:{fl:md5}})
        if remote:
            return data


    def _store_gathered(self):
        if self.cfg['data']:
            with open(self.cfg['filename'], 'w') as fp:
                json.dump(self.cfg['data'], fp)

    def do(self):
        self._gather()
        self._store_gathered()


class Checker(Gatherer):
    def __init__(self, cfg):
        self.report = dict()
        self.cfg = dict(cfg)
        self.cfg['data'] = self._prepare_structure()
        self.old_cfg = dict(cfg)
        try:
            with open(self.cfg['filename'], 'r') as fp:
                self.old_cfg['data'] = json.load(fp)
        except:
            usage("Datafile not accessible!")
        if self.cfg['release'] not in self.cfg['data'].keys():
            usage("Target release is not in database!")


    def _check(self, data, node):
        ip = node[0]
        self.report.update({ip:{}})
        for component in components:
            try:
                db = self.old_cfg['data'][self.cfg['release']][component]
                got = data[component]
                missing = set(db.keys()) - set(got.keys())
                self.report[ip][component] = {
                    "total": len(got.keys())
                }
                if len(missing) > 0:
                    self.report[ip][component].update({
                        "missing": len(missing),
                        "missing_names" : missing
                        }
                    )
                corrupt = set()
                for key in got.keys():
                    if got[key] != db[key]:
                        corrupt.add(key)
                if len(corrupt) > 0:
                    self.report[ip][component].update({
                        "corrupt": len(corrupt),
                        "corrupt_names": corrupt
                    })
            except KeyError as e:
                pass

    def _make_report(self):
        for node in self.report.keys():
            print ("\nReport for: " + node + " " + "=" * 56)
            if self.report[node] is None:
                print (">>>> NO DATA <<<<")
            else:
                for c in self.report[node].keys():
                    total = self.report[node][c]['total']
                    if self.report[node][c].has_key('missing'):
                        missed = self.report[node][c]['missing']
                    else:
                        missed = 0
                    if self.report[node][c].has_key('corrupt'):
                        corrupt = self.report[node][c]['corrupt']
                    else:
                        corrupt = 0
                    if missed == 0 and corrupt == 0:
                        msg = "{cmp:20}  =OK (Tested files:{cnt:4})".format(
                            cmp=c, cnt=total)
                    else:
                        msg = "{cmp:20}  =FAILED (Tested files:{cnt:4}/Missing:{miss:4}/Corrupt:{corr:4})".format(
                            cmp=c, cnt=total, miss=missed, corr=corrupt)
                    print (msg)
                    if self.cfg['verbose'] and self.report[node][c].has_key('corrupt_names'):
                        print ("    Corrupted files:")
                        print (textwrap.fill("{0}".format(
                            ", ".join(l for l in self.report[node][c]['corrupt_names'])),
                            initial_indent="    ",
                            subsequent_indent="    ",
                            width=80
                            ))
                        print("")
                    if self.cfg['verbose'] and self.report[node][c].has_key('missing_names'):
                        print ("    Missing files:")
                        print (textwrap.fill("{0}".format(
                            ", ".join(l for l in self.report[node][c]['missing_names'])),
                            initial_indent="    ",
                            subsequent_indent="    ",
                            width=80
                            ))
                        print("")


    def _get_nodes_json(self):
        try:
            psw = self.cfg['password']
            uname = self.cfg['username']
            tenant = self.cfg['tenant']

            req = urllib2.Request('http://127.0.0.1:5000/v2.0/tokens')
            req.add_header('Content-Type', 'application/json')
            req.add_data("""
                {{"auth":{{
                        "passwordCredentials":
                            {{
                                "password":"{psw}",
                                "username":"{uname}"
                            }},
                    "tenantName":"{tenant}"
                    }}
                }}
            """.format(psw=psw, uname=uname, tenant=tenant))
            token = json.load(urllib2.urlopen(req))['access']['token']['id']
            req = urllib2.Request('http://127.0.0.1:8000/api/v1/nodes')
            req.add_header('X-Auth-Token', token)
            return json.load(urllib2.urlopen(req))
        except Exception as e:
            usage("Can't connect to keystone/fuel at http://127.0.0.1")

    def _find_nodes(self):
        selected_nodes = list()
        for node in self._get_nodes_json():
            if node['cluster'] == self.cfg['env'] or self.cfg['all_envs'] is True:
                selected_nodes.append((node['ip'], node['os_platform']))
        return (selected_nodes)


    def do(self):
        to_check = self._find_nodes()
        for node in to_check:
            tmp = self._gather(node)
            self._check(tmp, node)
            tmp.clear()
        self._make_report()


def main():
    cfg = opts_parse()
    if cfg['action'] == 'gather':
        Actor = Gatherer(cfg)
    else:
        Actor = Checker(cfg)

    Actor.do()

if __name__ == "__main__":
    main()
