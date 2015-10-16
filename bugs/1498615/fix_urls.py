from six.moves import urllib

try:
    from glance.openstack.common import gettextutils
    gettextutils.install('glance')
except ImportError:
    from glance.openstack.common import _i18n


from glance.registry.client.v2 import client

OS_AUTH_TOKEN = "5434dde70b0a4bcc91c6f0455dafff03"
OS_REGISTRY_HOST = '192.168.0.3'
OS_REGISTRY_PORT = 9191


def fix_url(loc):
    url = loc['url']
    pieces = urllib.parse.urlparse(url)

    schemes = ('swift+http', 'swift+https')

    if pieces.scheme not in schemes:
        return None

    scheme = 'swift+config'
    ref = 'ref1'
    _, path = pieces.path.lstrip('/').split('/', 1)
    parts = (scheme, ref, path, None, None, None)
    new_url = urllib.parse.urlunparse(parts)
    loc['url'] = new_url
    return loc

if __name__ == '__main__':
    try:
        c = client.RegistryClient(
                 OS_REGISTRY_HOST, OS_REGISTRY_PORT, auth_tok=OS_AUTH_TOKEN)
    except TypeError:
        c = client.RegistryClient(
                 OS_REGISTRY_HOST, OS_REGISTRY_PORT, auth_token=OS_AUTH_TOKEN)

    images = c.image_get_all()

    for image in images:
        if image['status'] != 'active':
            continue
        locations = image['locations']
        image_id = image['id']
        for location in locations:
            fix_url(location)

        c.image_update(image_id=image_id, values={'locations': locations })

