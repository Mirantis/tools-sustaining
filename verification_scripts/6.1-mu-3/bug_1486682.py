import time

import unittest

import cinderclient.client
import glanceclient.client
import keystoneclient


PROP = {"hw_disk_bus": "ide",
        "hw_vif_model": "rtl8139"}

URL = 'http://192.168.0.2:5000/v2.0/'


class TestCinderBug1486682(unittest.TestCase):

    @staticmethod
    def add_properties(cli, image_id):
        for prop, val in PROP.iteritems():
            cli.image_tags.update(image_id, prop)
            tag = {prop: val}
            cli.images.update(image_id, **tag)

    @staticmethod
    def delete_properties(cli, image_id):
        list_props_to_delete = []
        for prop, _ in PROP.iteritems():
            list_props_to_delete.append(prop)
            cli.image_tags.delete(image_id, prop)
        cli.images.update(image_id, list_props_to_delete)

    @staticmethod
    def wait_to_status(cli, obj_id, expected_status='available'):
        timeout = 5 * 60
        start = int(time.time())
        status = cli.get(obj_id).status.lower()
        while status != expected_status:
            if status in ["error"]:
                raise StandardError("Object has error state.")
            time.sleep(10)
            status = cli.get(obj_id).status.lower()
            if int(time.time()) - start >= timeout:
                raise RuntimeError(
                    "Object has {} state after 5 minutes, but expected "
                    "status:{}".format(status, expected_status))

    def setUp(self):
        keystone = keystoneclient.v2_0.client.Client(
            username='admin',password='admin',tenant_name='admin',
            auth_url=URL)
        endpoint = keystone.service_catalog.url_for(service_type='image',
                                                    endpoint_type='publicURL')
        self.glance = glanceclient.client.Client(
            '2', endpoint, token=keystone.auth_token)
        self.cinder = cinderclient.client.Client(
            '1', 'admin', 'admin', 'admin', URL)
        images = [image['id'] for image in self.glance.images.list()
                  if image['name'] == "TestVM"]
        if not images:
            self.fail("image with name TestVM not found")
        self.image = images[0]
        self.vol = None
        self.add_properties(self.glance, self.image)

    def tearDown(self):
        self.delete_properties(self.glance, self.image)
        if self.vol:
            self.cinder.volumes.force_delete(self.vol)

    def test_1486682(self):
        self.vol = self.cinder.volumes.create(1, imageRef=self.image)
        self.wait_to_status(self.cinder.volumes, self.vol.id)
        print ("image dict")
        print self.glance.images.get(self.image)
        meta = self.cinder.volumes.get(self.vol.id).volume_image_metadata
        print ("volume image meta")
        print meta
        for tag, val in PROP.iteritems():
            if not meta.get(tag) == val:
                self.fail("Volume created from image not contains "
                          "meta:{} with value:{}".format(tag, val))
        print ("Yeah!!! Patch for bug:#1486682 works!!!")

if __name__ == "__main__":
    unittest.main()
