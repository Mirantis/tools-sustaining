#!/usr/bin/env python

from __future__ import print_function

import os
import re
import signal
import subprocess
import sys
import time

import libvirt
import netaddr

import scancodes

# CONST
UPDATE_HELPER = "update_helper.sh"
REPO_HELPER = "repo_helper.sh"
SSH_PARAMS = ["-o", "UserKnownHostsFile=/dev/null",
              "-o", "StrictHostKeyChecking=no"]

cfg = dict()
is_new = False

# required vars
cfg["ENV_NAME"] = os.getenv("ENV_NAME")
cfg["ISO_URL"] = os.getenv("ISO_URL")

# networks definition
cfg["ADMIN_NET"] = os.getenv("ADMIN_NET", "10.88.0.0/16")
cfg["PUBLIC_NET"] = os.getenv("PUBLIC_NET", "172.16.59.0/24")
cfg["PUB_SUBNET_SIZE"] = int(os.getenv("PUB_SUBNET_SIZE", 28))
cfg["ADM_SUBNET_SIZE"] = int(os.getenv("ADM_SUBNET_SIZE", 28))

# fuel node credentials
cfg["FUEL_SSH_USERNAME"] = os.getenv("FUEL_SSH_USERNAME", "root")
cfg["FUEL_SSH_PASSWORD"] = os.getenv("FUEL_SSH_PASSWORD", "r00tme")
cfg["KEYSTONE_USERNAME"] = os.getenv("KEYSTONE_USERNAME", "admin")
cfg["KEYSTONE_PASSWORD"] = os.getenv("KEYSTONE_PASSWORD", "admin")
cfg["KEYSTONE_TENANT"] = os.getenv("KEYSTONE_TENANT", "admin")

# nodes settings
cfg["ADMIN_RAM"] = int(os.getenv("ADMIN_RAM", 4096))
cfg["ADMIN_CPU"] = int(os.getenv("ADMIN_CPU", 2))
cfg["SLAVE_RAM"] = int(os.getenv("SLAVE_RAM", 3072))
cfg["SLAVE_CPU"] = int(os.getenv("SLAVE_CPU", 1))
cfg["NODES_COUNT"] = int(os.getenv("NODES_COUNT", 5))
cfg["NODES_DISK_SIZE"] = int(os.getenv("NODES_DISK_SIZE", 50))

cfg["STORAGE_POOL"] = os.getenv("STORAGE_POOL", "default")

cfg["ISO_DIR"] = os.getenv("PWD") + "/" + os.getenv("ISO_DIR", "iso") + "/"
if cfg["ISO_URL"]:
    cfg["ISO_PATH"] = cfg["ISO_DIR"] + cfg["ISO_URL"] \
        .split("/")[-1].split(".torrent")[0]
    # new releases such as 8.0 and 9.0 use new interface naming scheme
    # e.g. 'enp0s4' instead of 'eth1' so we should get version of Fuel from ISO name
    new_versions = ["8.0", "9.0", "10.0", "11.0"]
    is_new = any(v in cfg["ISO_URL"] for v in new_versions)

cfg["PREPARE_CLUSTER"] = os.getenv("PREPARE_CLUSTER")
cfg["UPDATE_FUEL"] = os.getenv("UPDATE_FUEL")
cfg["ADD_CENT_REPO"] = os.getenv("ADD_CENT_REPO")
cfg["RELEASE"] = os.getenv("RELEASE")
cfg["HA"] = os.getenv("HA")
cfg["NETWORK_TYPE"] = os.getenv("NETWORK_TYPE")

try:
    vconn = libvirt.open("qemu:///system")
except:
    print ("\nERROR: libvirt is inaccessible!")
    sys.exit(10)

try:
    dnl = open(os.devnull, 'w')
except:
    dnl = None

class SSHHost:
    def __init__(self, conn_line=None, usr=None, subnet=None, pswd="r00tme"):
        if subnet is not None:
            self.conn_line = self._calculate_conn_line(usr, subnet)

        if  conn_line is not None:
            self.conn_line = conn_line

        self.pswd=pswd

    def _calculate_conn_line(self, usr, subnet):
        admip = str(subnet.ip + 2)
        return "{usr}@{admip}".format(usr=usr, admip=admip)

    def execute(self, command):
        return sshpass(
            psw = self.pswd,
            ssh_cmd = ["ssh"]+SSH_PARAMS+[self.conn_line]+command,
        )

    def put_file(self, filename, dest="/tmp/"):
        return sshpass (
            psw = self.pswd,
            ssh_cmd = ["scp"]+SSH_PARAMS+['./'+filename,self.conn_line+":"+dest],
        )


def pprint_dict(subj):
    if not isinstance(subj, dict):
        return False
    for k, v in sorted(subj.items()):
        print (" {0:20}: {1}".format(k, v))


def get_free_subnet_from_libvirt():
    occupied_nets = set()
    for net in vconn.listAllNetworks():
        res = re.findall("<ip address=\'(.*)\' prefix=\'(.*)\'>",
                         net.XMLDesc())
        try:
            occupied_nets.add(netaddr.IPNetwork(
                "{0}/{1}".format(res[0][0], res[0][1])))
        except IndexError:
            pass

    admin_subnets = set(
        x for x in netaddr.IPNetwork(cfg["ADMIN_NET"])
                          .subnet(cfg["ADM_SUBNET_SIZE"])
        if x not in occupied_nets
    )
    public_subnets = set(
        x for x in netaddr.IPNetwork(cfg["PUBLIC_NET"])
                          .subnet(cfg["PUB_SUBNET_SIZE"])
        if x not in occupied_nets
    )

    if not admin_subnets or not public_subnets:
        print ("\nERROR: No more NETWORKS to associate!")
        return False

    cfg["ADMIN_SUBNET"] = sorted(admin_subnets)[0]
    cfg["PUBLIC_SUBNET"] = sorted(public_subnets)[0]
    print (
        "The following subnets will be used:\n"
        " ADMIN_SUBNET:   {0}\n"
        " PUBLIC_SUBNET:  {1}\n".format(cfg["ADMIN_SUBNET"],
                                        cfg["PUBLIC_SUBNET"])
    )
    return True


def download_iso():
    try:
        os.makedirs(cfg["ISO_DIR"])
    except os.error as err:
        if err.args[0] != 17:
            print ("Error during creating directory {0}: {1}".format(
                cfg["ISO_DIR"], err.args[1]))
            sys.exit(15)

    cmd = ["aria2c", "-d", cfg["ISO_DIR"], "--seed-time=0",
           "--allow-overwrite=true", "--force-save=true",
           "--auto-file-renaming=false", "--allow-piece-length-change=true",
           "--log-level=error", cfg["ISO_URL"]]

    proc = subprocess.Popen(
        cmd,
        stdin=None,
        stdout=None,
        stderr=None,
        bufsize=1
    )
    proc.wait()

    if proc.returncode == 0:
        print("\nISO successfully downloaded")
    else:
        print("\nERROR: Cannot download ISO")
        sys.exit(20)


def define_nets():
    network_xml_template = \
        "<network>\n" \
        " <name>{net_name}</name>\n" \
        " <forward mode='route'/>\n" \
        " <ip address='{ip_addr}' prefix='{subnet}'>\n" \
        " </ip>\n" \
        "</network>\n"
    net_name = cfg["ENV_NAME"]+"_adm"
    ip_addr = str(cfg["ADMIN_SUBNET"].ip + 1)
    subnet = cfg["ADMIN_SUBNET"].prefixlen

    net_xml = network_xml_template.format(net_name=net_name,
                                          ip_addr=ip_addr,
                                          subnet=subnet)

    print ("Prepared admin_net xml:\n\n{0}".format(net_xml))

    try:
        cfg["ADM_SUBNET_OBJ"] = vconn.networkCreateXML(net_xml)
    except:
        print ("\nERROR: Unable to create admin subnet in libvirt!")
        sys.exit(11)

    net_name = cfg["ENV_NAME"]+"_pub"
    ip_addr = str(cfg["PUBLIC_SUBNET"].ip + 1)
    subnet = cfg["PUBLIC_SUBNET"].prefixlen

    net_xml = network_xml_template.format(net_name=net_name,
                                          ip_addr=ip_addr,
                                          subnet=subnet)

    print ("Prepared public_net xml:\n\n{0}".format(net_xml))

    try:
        cfg["PUB_SUBNET_OBJ"] = vconn.networkCreateXML(net_xml)
    except:
        print ("\nERROR: Unable to create public subnet in libvirt!")
        sys.exit(11)

    print ("Networks have been successfully created.")


def volume_create(name):
    vol_template = \
        "<volume type='file'>\n" \
        " <name>{vol_name}.img</name>\n" \
        " <allocation>0</allocation>\n" \
        " <capacity unit='G'>{vol_size}</capacity>\n" \
        " <target>\n" \
        "  <format type='qcow2'/>\n" \
        " </target>\n" \
        "</volume>\n"
    try:
        pool = vconn.storagePoolLookupByName(cfg["STORAGE_POOL"])
    except:
        print("\nERROR: libvirt`s storage pool '{0}' is not accessible!"
              .format(cfg["STORAGE_POOL"]))
        sys.exit(12)

    volume = vol_template.format(vol_name=name,
                                 vol_size=cfg["NODES_DISK_SIZE"])

    try:
        vol_object = pool.createXML(volume)
    except:
        print("\nERROR: unable to create volume '{0}'!"
              .format(name))
        sys.exit(13)
    print("Created volume from XML:\n\n{0}".format(volume))
    return vol_object


def define_nodes():
    pass


def start_node(name, admin=False):
    vol_obj = volume_create(name)

    node_template_xml = """
<domain type='kvm'>
  <name>{name}</name>
  <memory unit='KiB'>{memory}</memory>
  <currentMemory unit='KiB'>{memory}</currentMemory>
  <vcpu placement='static'>{vcpu}</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='{first_boot}'/>
    <boot dev='{second_boot}'/>
    <bios rebootTimeout='5000'/>
  </os>
  <cpu mode='host-model'>
    <model fallback='forbid'/>
  </cpu>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup' track='wall'>
      <catchup threshold='123' slew='120' limit='10000'/>
    </timer>
    <timer name='hpet' present='yes'/>
    <timer name='kvmclock' present='yes'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='unsafe'/>
      <source file='{hd_volume}'/>
      <target dev='sda' bus='virtio'/>
    </disk>
{iso}
    <controller type='usb' index='0' model='nec-xhci'>
      <alias name='usb0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x08' function='0x0'/>
    </controller>
    <controller type='pci' index='0' model='pci-root'>
      <alias name='pci.0'/>
    </controller>
    <controller type='ide' index='0'>
      <alias name='ide0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x1'/>
    </controller>
    <interface type='network'>
      <source network='{admin_net}'/>
      <model type='e1000'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <interface type='network'>
      <source network='{public_net}'/>
      <model type='e1000'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </interface>
    <serial type='pty'>
      <source path='/dev/pts/6'/>
      <target port='0'/>
      <alias name='serial0'/>
    </serial>
    <console type='pty' tty='/dev/pts/6'>
      <source path='/dev/pts/6'/>
      <target type='serial' port='0'/>
      <alias name='serial0'/>
    </console>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='5900' autoport='yes' listen='0.0.0.0'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    <video>
      <model type='vga' vram='9216' heads='1'/>
      <alias name='video0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <alias name='balloon0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x0a' function='0x0'/>
    </memballoon>
  </devices>
</domain>
    """
    if admin:

        vcpu = cfg["ADMIN_CPU"]
        memory = cfg["ADMIN_RAM"] * 1024
        first_boot = "hd"
        second_boot = "cdrom"
        iso = """    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw' cache='unsafe'/>
      <source file='{iso_path}'/>
      <target dev='hdb' bus='ide'/>
      <readonly/>
    </disk>""".format(iso_path=cfg["ISO_PATH"])

    else:

        vcpu = cfg["SLAVE_CPU"]
        memory = cfg["SLAVE_RAM"] * 1024
        first_boot = "network"
        second_boot = "hd"
        iso = ""

    admin_net = cfg["ADM_SUBNET_OBJ"].name()
    public_net = cfg["PUB_SUBNET_OBJ"].name()
    hd_volume = vol_obj.path()

    xml = node_template_xml.format(
        name=name,
        vcpu=vcpu,
        memory=memory,
        first_boot=first_boot,
        second_boot=second_boot,
        hd_volume=hd_volume,
        iso=iso,
        admin_net=admin_net,
        public_net=public_net
    )

    print ("Prepared XML for node:\n{0}".format(xml))
    try:
        instance = vconn.createXML(xml)
    except Exception as e:
        print (e)
        sys.exit(100)
    if admin:
        send_keys(instance)


def send_keys(instance):
    keys = (
        "<Wait>\n"
        "<Esc><Enter>\n"
        "<Wait>\n"
        "vmlinuz initrd=initrd.img ks=cdrom:/ks.cfg\n"
        " ip={ip}\n"
        " netmask={netmask}\n"
        " gw={gw}\n"
        " dns1={dns}\n"
        " showmenu=no\n"
        " <Enter>\n"
    ).format(
        ip=str(cfg["ADMIN_SUBNET"].ip + 2),
        netmask=str(cfg["ADMIN_SUBNET"].netmask),
        gw=str(cfg["ADMIN_SUBNET"].ip + 1),
        dns="172.18.16.10", #Moscow DNS
    )
    print (keys)
    key_codes = scancodes.from_string(str(keys))
    for key_code in key_codes:
        if isinstance(key_code[0], str):
            if key_code[0] == 'wait':
                time.sleep(1)
            continue
        instance.sendKey(0, 0, list(key_code), len(key_code), 0)
    pass


def inject_ifconfig_ssh():

    iface = "eth1" if not is_new else "enp0s4"
    rule = \
        "DEVICE={iface}\n" \
        "ONBOOT=yes\n" \
        "BOOTPROTO=static\n" \
        "NM_CONTROLLED=no\n" \
        "IPADDR={ip}\n" \
        "NETMASK={netmask}\n" \
        "GATEWAY={gw}\n" \
        "DNS1={dns}\n" \
        .format(
            iface=iface,
            ip=str(cfg["PUBLIC_SUBNET"].ip + 2),
            netmask=str(cfg["PUBLIC_SUBNET"].netmask),
            gw=str(cfg["PUBLIC_SUBNET"].ip + 1),
            dns=str(cfg["ADMIN_SUBNET"].ip + 1)
        )
    print ("\nTo fuel:\n{0}".format(rule))
    ifcfg = "/etc/sysconfig/network-scripts/ifcfg-{iface}".format(iface=iface)
    psw = cfg["FUEL_SSH_PASSWORD"]
    usr = cfg["FUEL_SSH_USERNAME"]
    admip = str(cfg["ADMIN_SUBNET"].ip + 2)
    cmd = [
        "sshpass",
        "-p",
        psw,
        "ssh",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "{usr}@{admip}".format(usr=usr, admip=admip),
        "cat - > {ifcfg} ; /sbin/ifup {iface}".format(ifcfg=ifcfg, iface=iface)
    ]

    retries = 0
    while True:
        if retries > 25:
            return False

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=dnl
        )

        print(proc.communicate(input=rule)[0])

        proc.wait()

        if proc.returncode == 0:
            print("Inject successful!")
            return True
        else:
            retries += 1
            print("{0}...".format(retries), end='')
            time.sleep(60)

def sshpass(psw,ssh_cmd):
    cmd = [
        "sshpass",
        "-p",
        psw,
    ] + ssh_cmd

    proc = subprocess.Popen(
        cmd,
        stdin=dnl,
    )

    proc.wait()

    if proc.returncode == 0:
        return True
    else:
        print("ERROR: command "+' '.join(cmd)+" failed.")
        return False


def add_cent_repo(node, repolist):
    if node.put_file(REPO_HELPER):
        i = 1
        for repo in repolist.split('\n'):
            if not node.execute(["/tmp/"+REPO_HELPER,"add"+str(i), repo]):
                print ("ERROR: Unable to add repo " + repo)
                return False
            i = i + 1
        return True
    else:
        print ("ERROR: Unable to copy repo script to admin node")
        return False


def do_update(node):
    if node.put_file(UPDATE_HELPER):
        return node.execute(["/tmp/"+UPDATE_HELPER])
    else:
        print ("ERROR: Unable to copy update script to admin node")
        return False


def start_slaves():
    for num in range(cfg["NODES_COUNT"]):
        name = "{0}_slave_{1}".format(cfg["ENV_NAME"], num)
        print ("Starting: {0}".format(name))
        start_node(name)


def wait_for_api_is_ready():
    cmd = ["sshpass", "-p", cfg["FUEL_SSH_PASSWORD"], "ssh", "-o"
           "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no",
           "{usr}@{admip}".format(usr=cfg["FUEL_SSH_USERNAME"],
                                  admip=str(cfg["ADMIN_SUBNET"].ip + 2)),
           "/usr/bin/fuel env"]
    print("Waiting until Nailgun API is ready: ", end='')
    retries = 0
    while retries < 50:
        proc = subprocess.Popen(cmd, stdin=None, stdout=dnl, stderr=dnl)
        proc.wait()
        if proc.returncode == 0:
            print("\nNailgun API seems to be ready, waiting 60 sec.")
            time.sleep(60)
            return True
        else:
            retries += 1
            print("{0}...".format(retries), end='')
            time.sleep(60)
    return False


def configure_nailgun():
    if cfg["PREPARE_CLUSTER"] == "false":
        return

    conf_opts = {
        "HA": "--mode ha" if not is_new else "",
        "NO_HA": "--mode multinode",
        "neutron_vlan": "--net neutron --nst vlan" if not is_new else "--nst vlan",
        "neutron_gre": "--net neutron --nst gre" if not is_new else "--nst gre",
        "neutron_tun": "--net neutron --nst tun" if not is_new else "--nst tun",
        "nova": "--net nova" if not is_new else "",
        "Ubuntu": 2,
        "CentOS": 1
    }

    if cfg["NETWORK_TYPE"] == "nova":
        sed = "/bin/sed -i -e 's/cidr: 172.16.0.0\/24$/cidr: {pub_net}\/{prefix}/g'" \
            " -e 's/gateway: 172.16.0.1$/gateway: {pub_gw}/g'" \
            " -e 's/- 172.16.0.2$/- {pstart}/g'" \
            " -e 's/- 172.16.0.127$/- {pend}/g'" \
            " -e 's/- 172.16.0.128$/- {fstart}/g'" \
            " -e 's/- 172.16.0.254$/- {fend}/g' /root/network_1.yaml;"
    else:
        sed = "/bin/sed -i -e 's/cidr: 172.16.0.0\/24$/cidr: {pub_net}\/{prefix}/g'" \
            " -e 's/gateway: 172.16.0.1$/gateway: {pub_gw}/g'" \
            " -e 's/- 172.16.0.2$/- {pstart}/g'" \
            " -e 's/- 172.16.0.126$/- {pend}/g'" \
            " -e 's/- 172.16.0.130$/- {fstart}/g'" \
            " -e 's/- 172.16.0.254$/- {fend}/g' /root/network_1.yaml;" \
            "sed -i -e '/public_network_assignment:$/" \
            "{{:a N; s/value:.*$/value: true/; t b ; ba ; :b }}' /root/settings_1.yaml;"

    sed = sed.format(
        pub_net=str(cfg["PUBLIC_SUBNET"].ip),
        prefix=cfg["PUBLIC_SUBNET"].prefixlen,
        pub_gw=str(cfg["PUBLIC_SUBNET"].ip + 1),
        pstart=str(cfg["PUBLIC_SUBNET"].ip + 3),
        pend=str(cfg["PUBLIC_SUBNET"].ip + 4 + int(cfg["NODES_COUNT"])),
        fstart=str(cfg["PUBLIC_SUBNET"].ip + 5 + int(cfg["NODES_COUNT"])),
        fend=str(netaddr.IPAddress(cfg["PUBLIC_SUBNET"].last) - 1)
    )

    cmd = [
        "sshpass",
        "-p",
        cfg["FUEL_SSH_PASSWORD"],
        "ssh",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=no",
        "{usr}@{admip}".format(usr=cfg["FUEL_SSH_USERNAME"],
                               admip=str(cfg["ADMIN_SUBNET"].ip + 2)),
        "sed -i -e'/^ListenAddress.*$/d' /etc/ssh/sshd_config ; service sshd reload;"
        "iptables -I INPUT -p tcp -m tcp --dport 22 -j ACCEPT;"
        "/usr/bin/fuel env -c --name {name} --release {release} {ha} {network};"
        "/usr/bin/fuel settings --env-id 1 --download;"
        "/usr/bin/fuel network --env-id 1 -d; {sed}"
        "/usr/bin/fuel settings --env-id 1 --upload;"
        "/usr/bin/fuel network --env-id 1 -u".format(
            name=cfg["ENV_NAME"],
            release=conf_opts[cfg["RELEASE"]],
            ha=conf_opts[cfg["HA"]],
            network=conf_opts[cfg["NETWORK_TYPE"]],
            sed=sed
        )
    ]

    print(cmd)
    proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=dnl)
    proc.wait()
    if proc.returncode == 0:
        print ("\nNailgun has been configured")
        return True
    time.sleep(60)
    print("Retrying")
    proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=dnl)
    proc.wait()
    if proc.returncode == 0:
        print ("\nNailgun has been configured")
        return True
    else:
        print ("\nERROR: Nailgun has not been configured even after 2nd retry")
        return False


def wait_for_cluster_is_ready():
    pass


def cleanup():
    """
    Cleanup procedure now always returns success
    """
    for vm in vconn.listAllDomains():
        if vm.name().startswith(cfg["ENV_NAME"]):
            vm.destroy()
    for net in vconn.listAllNetworks():
        if net.name().startswith(cfg["ENV_NAME"]):
            net.destroy()
    for vol in vconn.storagePoolLookupByName(cfg["STORAGE_POOL"]) \
                    .listAllVolumes():
        if vol.name().startswith(cfg["ENV_NAME"]):
            vol.delete()


def print_summary():
    summary = """
=================================== SUMMARY ===================================
PLEASE USE FOLLOWING CONFIGURATION
FOR CLUSTER'S NETWORKS

PUBLIC:
                         START            END
        IP RANGE  {pub_start:20} {pub_end}
        CIDR      {pub_subnet:20}
        GATEWAY   {gw:20}
        FLOATING  {float_start:20} {float_end}""" \
    .format(
        pub_start=str(cfg["PUBLIC_SUBNET"].ip + 3),
        pub_end=str(cfg["PUBLIC_SUBNET"].ip + 4 + int(cfg["NODES_COUNT"])),
        pub_subnet=str(cfg["PUBLIC_SUBNET"]),
        gw=str(cfg["PUBLIC_SUBNET"].ip + 1),
        float_start=str(cfg["PUBLIC_SUBNET"].ip + 5 + int(cfg["NODES_COUNT"])),
        float_end=str(netaddr.IPAddress(cfg["PUBLIC_SUBNET"].last) - 1)
    )
    print(summary)
    print ("\nFUEL ACCESS:\n\thttp://{0}:8000".format(
        str(cfg["PUBLIC_SUBNET"].ip + 2)))
    print ("\nVNC CONSOLES:\n")
    for dom in vconn.listAllDomains():
        if dom.name().startswith(cfg["ENV_NAME"]):
            vncport = re.findall("graphics\stype=\'vnc\'\sport=\'(\d+)\'",
                                 dom.XMLDesc())[0]
            hostname = os.uname()[1]
            print("\t{0:40} {1}:{2}".format(dom.name(), hostname, vncport))
    print("\nNAME OF THE ENVIRONMENT (USED IN 'DESTROY_CLUSTER' JOB):\n\t{0}"
          .format(cfg["ENV_NAME"]))
    print("""
=================================== SUMMARY ===================================
    """)


def main():
    """
    ENV_NAME must be unique, this is by default provided by Jenkins
    unique BUILD_NUMBER
    """
    if '--destroy' in sys.argv:
        # ignore SIGTERM & SIGINT to have a chance to make cleanup
        # uninterrupted in case if multiple signals are coming
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)

        print("Destroying {0}".format(cfg["ENV_NAME"]))
        cleanup()
        sys.exit(0)

    print("Starting script with the following options:\n")
    pprint_dict(cfg)

    download_iso()

    if cfg["ENV_NAME"] is None:
        print ("\nERROR: $ENV_NAME must be set!")
        sys.exit(1)
    if cfg["ISO_URL"] is None:
        print ("\nERROR: $ISO_URL must be set!")
        sys.exit(2)
    if not get_free_subnet_from_libvirt():
        sys.exit(3)

    define_nets()

    define_nodes()

    start_node(cfg["ENV_NAME"]+"_admin", admin=True)

    time.sleep(60 * 5)

    inject_ifconfig_ssh()


    wait_for_api_is_ready()

    admin_node=SSHHost(usr = cfg["FUEL_SSH_USERNAME"],
        subnet=cfg["ADMIN_SUBNET"],
        pswd = cfg["FUEL_SSH_PASSWORD"],)

    if cfg["ADD_CENT_REPO"]!="" and cfg["ADD_CENT_REPO"] is not None:
        add_cent_repo(admin_node,cfg["ADD_CENT_REPO"])

    if cfg["UPDATE_FUEL"]=="true":
        if do_update(admin_node):
            print("fuel update complete")
        else:
            print("ERROR: unable to update fuel")

    start_slaves()

    configure_nailgun()

    wait_for_cluster_is_ready()

    print_summary()

    vconn.close()

    dnl.close()

if __name__ == "__main__":
    main()
