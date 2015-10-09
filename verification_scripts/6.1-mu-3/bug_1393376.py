import time

import unittest

import keystoneclient
import neutronclient.neutron.client
import novaclient.client
import heatclient.v1.client

URL = 'http://192.168.0.2:5000/v2.0/'

NAME = "test_1393376"

TMPL1 = """
heat_template_version: 2013-05-23

description: Sample Stack

resources:

  instance-port:
    type: OS::Neutron::Port
    properties:
      network_id: {net_id}

  instance:
    type: OS::Nova::Server
    properties:
      flavor: m1.micro
      image: TestVM
      networks:
        - port : { get_resource : instance-port }
"""

TMPL2 = """
heat_template_version: 2013-05-23

description: Sample Stack

resources:

  instance-port:
    type: OS::Neutron::Port
    properties:
      network_id: {net_id}

  instance:
    type: OS::Nova::Server
    properties:
      flavor: m1.micro
      image: TestVM
      networks:
        - port : { get_resource : instance-port }

  instance2-port:
    type: OS::Neutron::Port
    properties:
      network_id: {net_id}

  instance2:
    type: OS::Nova::Server
    properties:
      flavor: m1.micro
      image: TestVM
      networks:
        - port : { get_resource : instance2-port }
"""


class TestHeatBug1393376(unittest.TestCase):

    @staticmethod
    def wait_to_status(cli, stack_id, expected_status='CREATE_COMPLETE'):
        timeout = 5 * 60
        start = int(time.time())
        status = cli.stacks.get(stack_id).stack_status
        while status != expected_status:
            if status in ["CREATE_FAILED", "UPDATE_FAILED"]:
                raise StandardError("Heat stack has FAILED state.")
            time.sleep(10)
            status = cli.stacks.get(stack_id).stack_status
            if int(time.time()) - start >= timeout:
                raise RuntimeError(
                    "Heat stack has {} state after 5 minutes, but expected "
                    "status:{}".format(status, expected_status))

    def setUp(self):
        keystone = keystoneclient.v2_0.client.Client(
            username='admin',password='admin',tenant_name='admin',auth_url=URL)
        n_endpoint = keystone.service_catalog.url_for(
            service_type='network',endpoint_type='publicURL')
        self.neutron = neutronclient.neutron.client.Client(
            '2.0',token=keystone.auth_token,endpoint_url=n_endpoint)
        h_endpoint = keystone.service_catalog.url_for(
            service_type='orchestration',endpoint_type='publicURL')
        self.heat = heatclient.v1.client.Client(h_endpoint,
                                                token=keystone.auth_token)
        self.nova = novaclient.client.Client(
            '2', 'admin', 'admin', 'admin', URL, service_type='compute',
            no_cache=True)
        private_nets = self.neutron.list_networks(
            **{"router:external":False})['networks']
        if not private_nets:
            self.fail("Private network not found")
        self.net = private_nets[0]['id']
        self.stack = None

    def tearDown(self):
        if self.stack:
            self.heat.stacks.delete(self.stack.id)

    def test_1393376(self):
        self.heat.stacks.create(stack_name=NAME,
                                template=TMPL1.replace("{net_id}", self.net))
        self.stack = [i for i in self.heat.stacks.list()
                      if i.stack_name == NAME][0]
        self.wait_to_status(self.heat, self.stack.id)
        self.heat.stacks.update(self.stack.id,
                                template=TMPL2.replace("{net_id}", self.net))
        self.wait_to_status(self.heat, self.stack.id,
                            expected_status="UPDATE_COMPLETE")
        stack_instances = [i.id for i in self.nova.servers.list()
                           if i.name.startswith(NAME)]
        for instance in stack_instances:
            if not self.neutron.list_ports(device_id=instance)['ports']:
                self.fail("Neutron port for instance:{} not found. "
                          "Bug #1393376 reproduced. FAIL.".format(instance))
        print "Yeah!!! Bug #1393376 not reproduced. Fix works."


if __name__ == "__main__":
    unittest.main()
