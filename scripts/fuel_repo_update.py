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
import urllib2
from keystoneclient.v2_0 import client

if __name__ == "__main__":
    username = 'admin'
    password = 'admin'
    tenant = 'admin'
    auth = 'http://127.0.0.1:5000/v2.0'
    releases = 'http://127.0.0.1:8000/api/v1/releases/{0}/'

    ks = client.Client (username=username, password=password,
            tenant_name=tenant, auth_url=auth)
    token = ks.auth_token

    for release in xrange(1,3):
        req = urllib2.Request(releases.format(release))
        req.add_header('X-Auth-Token',token)
        instance = json.load(urllib2.urlopen(req))
        repo_metadata = instance['orchestrator_data']['repo_metadata']

        if repo_metadata.has_key('updates'):
            print ("Updates repositiry is already installed for {0}".format(
                                                instance['operating_system']))
            continue
        if instance['operating_system'] == 'Ubuntu':
            repo_metadata.update({u'updates':
                u'http://10.20.0.2:8080/updates/ubuntu precise main'})
        else:
            repo_metadata.update({u'updates':
                u'http://10.20.0.2:8080/updates/centos/os/x86_64'})

        req = urllib2.Request(releases.format(release), data=json.dumps(instance))
        req.add_header('X-Auth-Token',token)
        req.get_method = lambda: 'PUT'
        print ("Pushing changes")
        try:
            urllib2.urlopen(req)
        except urllib2.HTTPError as e:
            print ("Changes can't be applied: {0}".format(e.args[0]))

