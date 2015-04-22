#!/usr/bin/env python

import os
import re
import sqlite3
import subprocess
import sys
import time

import libvirt
import netaddr

import scancodes

cfg = dict()
# required vars
cfg["ENV_NAME"] = os.getenv("ENV_NAME")
cfg["ISO_URL"] = os.getenv("ISO_URL")

# networks defenition
cfg["ADMIN_NET"] = os.getenv("ADMIN_NET", "10.88.0.0/16")
cfg["PUBLIC_NET"] = os.getenv("PUBLIC_NET", "172.16.59.0/24")
cfg["PUB_SUBNET_SIZE"] = int(os.getenv("PUB_SUBNET_SIZE", 28))
cfg["ADM_SUBNET_SIZE"] = int(os.getenv("ADM_SUBNET_SIZE", 28))

#DB
cfg["DB_FILE"] = os.getenv("DB_FILE", "build_cluster.db")

#fuel node credentials
cfg["FUEL_SSH_USERNAME"] = os.getenv("FUEL_SSH_USERNAME", "root")
cfg["FUEL_SSH_PASSWORD"] = os.getenv("FUEL_SSH_PASSWORD", "r00tme")
cfg["KEYSTONE_USERNAME"] = os.getenv("KEYSTONE_USERNAME", "admin")
cfg["KEYSTONE_PASSWORD"] = os.getenv("KEYSTONE_PASSWORD", "admin")
cfg["KEYSTONE_TENANT"] = os.getenv("KEYSTONE_TENANT", "admin")

#nodes settings
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

cfg["PREPARE_CLUSTER"] = os.getenv("PREPARE_CLUSTER")
cfg["RELEASE"] = os.getenv("RELEASE")
cfg["HA"] = os.getenv("HA")
cfg["NETWORK_TYPE"] = os.getenv("NETWORK_TYPE")

db = None

try:
    vconn = libvirt.open("qemu:///system")
except:
    print ("\nERRROR: libvirt is inaccessible!")
    sys.exit(10)


def initialize_database():
    """ This functions initializes DB
        either by creating it or just opening
    """
    global db

    db = sqlite3.Connection(cfg["DB_FILE"])
    cursor = db.cursor()
    try:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS nets ("
            "net TEXT, "
            "env TEXT, "
            "interface TEXT);"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS envs ("
            "env TEXT, "
            "owner TEXT, "
            "nodes_count INT, "
            "admin_ram INT, "
            "admin_cpu INT, "
            "slave_ram INT, "
            "slave_cpu INT, "
            "deploy_type INT);"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS disks ("
            "env TEXT, "
            "node TEXT, "
            "filename TEXT);"
        )
    except:
        print ("Unable to open/create database {0}".format(cfg["DB_FILE"]))
        sys.exit(5)


def pprint_dict(subj):
    if not isinstance(subj, dict):
        return False
    for k, v in sorted(subj.items()):
        print (" {0:20}: {1}".format(k, v))


def env_is_available():
    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM nets WHERE env='{0}';".format(cfg["ENV_NAME"])
    )

    if cursor.fetchone() is None:
        return True
    else:
        return False


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
        "Following subnets will be used:\n"
        " ADMIN_SUBNET:   {0}\n"
        " PUBLIC_SUBNET:  {1}\n".format(cfg["ADMIN_SUBNET"],
                                        cfg["PUBLIC_SUBNET"])
    )
    sql_query = [
        (str(cfg["ADMIN_SUBNET"]), str(cfg["ENV_NAME"]),
         str(cfg["ENV_NAME"] + "_adm")),
        (str(cfg["PUBLIC_SUBNET"]), str(cfg["ENV_NAME"]),
         str(cfg["ENV_NAME"] + "_pub"))
    ]
    print sql_query
    cursor = db.cursor()
    cursor.executemany("INSERT INTO nets VALUES (?,?,?)", sql_query)
    db.commit()
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
        print("\nISO successfuly downloaded")
    else:
        print("\nERROR: Cannot download ISO")
        sys.exit(20)


def register_env():
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO envs VALUES ('{0}','{1}',{2},{3},{4},{5},{6},{7});"
        .format(cfg["ENV_NAME"], "nobody", cfg["NODES_COUNT"],
                cfg["ADMIN_RAM"], cfg["ADMIN_CPU"], cfg["SLAVE_RAM"],
                cfg["SLAVE_CPU"], 1)
    )
    db.commit()


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

    print ("Networks have been successfuly created.")


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
    <type arch='x86_64' machine='pc-i440fx-trusty'>hvm</type>
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
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
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
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <interface type='network'>
      <source network='{public_net}'/>
      <model type='virtio'/>
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
        first_boot = "hd"
        second_boot = "network"
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
        " dns1={gw}\n"
        " <Enter>\n"
    ).format(
        ip=str(cfg["ADMIN_SUBNET"].ip + 2),
        netmask=str(cfg["ADMIN_SUBNET"].netmask),
        gw=str(cfg["ADMIN_SUBNET"].ip + 1)
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
    rule = \
        "DEVICE=eth1\n" \
        "ONBOOT=yes\n" \
        "BOOTPROTO=static\n" \
        "NM_CONTROLLED=no\n" \
        "IPADDR={ip}\n" \
        "PREFIX={prefix}\n" \
        "GATEWAY={gw}\n" \
        .format(
            ip=str(cfg["PUBLIC_SUBNET"].ip + 2),
            prefix=str(cfg["PUBLIC_SUBNET"].prefixlen),
            gw=str(cfg["PUBLIC_SUBNET"].ip + 1)
        )
    print ("\nTo fuel:\n{0}".format(rule))
    ifcfg = "/etc/sysconfig/network-scripts/ifcfg-eth1"
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
        "cat - > {ifcfg} ; /etc/init.d/network restart".format(ifcfg=ifcfg)
    ]

    retries = 0
    while True:
        if retries > 10:
            return False

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None
        )

        print(proc.communicate(input=rule)[0])

        proc.wait()

        if proc.returncode == 0:
            print("Inject successful")
            return True
        else:
            retries += 1
            print("Retry # {0} in 60 seconds".format(retries))
            time.sleep(60)


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

    retries = 0
    while retries < 20:
        proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
        proc.wait()
        if proc.returncode == 0:
            print ("\nNailgun API seems to be ready, waiting 60 sec.")
            time.sleep(60)
            return True
        else:
            retries += 1
            print ("\nNailgun API is not ready. Retry in 60 seconds")
            time.sleep(60)
    return False


def configure_nailgun():
    if cfg["PREPARE_CLUSTER"] == "false":
        return

    conf_opts = {
        "HA": "--mode ha",
        "NO_HA": "--mode multinode",
        "neutron_vlan": "--net neutron --nst vlan",
        "neutron_gre": "--net neutron --nst gre",
        "nova": "--net nova",
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
    proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
    proc.wait()
    if proc.returncode == 0:
        print ("\nNailgun has been configured")
        return True
    time.sleep(60)
    print("Retry")
    proc = subprocess.Popen(cmd, stdin=None, stdout=None, stderr=None)
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
    if env_is_available():
        print("{0} environment is not exist!".format(cfg["ENV_NAME"]))
        sys.exit(127)

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

    cursor = db.cursor()
    cursor.execute(
        "DELETE FROM nets WHERE env='{0}'".format(cfg["ENV_NAME"])
    )
    cursor.execute(
        "DELETE FROM envs WHERE env='{0}'".format(cfg["ENV_NAME"])
    )
    db.commit()


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
    #os.uname()[1] - hostname
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
    initialize_database()
    print("\nDatabase ready.\n")
    if '--destroy' in sys.argv:
        print("Destroying {0}".format(cfg["ENV_NAME"]))
        cleanup()
        db.close()
        sys.exit(0)
    print("Starting script with following options:\n")
    pprint_dict(cfg)

    download_iso()

    if cfg["ENV_NAME"] is None:
        print ("\nERROR: $ENV_NAME must be set!")
        sys.exit(1)
    if cfg["ISO_URL"] is None:
        print ("\nERROR: $ISO_URL must be set!")
        sys.exit(2)
    if not env_is_available():
        print ("\nERROR: $ENV_NAME must be unique! {0} already exists"
               .format(cfg["ENV_NAME"]))
        sys.exit(4)

    if not get_free_subnet_from_libvirt():
        sys.exit(3)

    register_env()

    define_nets()

    define_nodes()

    start_node(cfg["ENV_NAME"]+"_admin", admin=True)

    time.sleep(60 * 5)

    inject_ifconfig_ssh()

    start_slaves()

    print_summary()

    wait_for_api_is_ready()

    configure_nailgun()

    wait_for_cluster_is_ready()

    db.close()
    vconn.close()
if __name__ == "__main__":
    main()
