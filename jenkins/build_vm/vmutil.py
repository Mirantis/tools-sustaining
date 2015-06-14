#!/usr/bin/env python

from argparse import ArgumentParser
from datetime import datetime
from functools import wraps
from inspect import getargspec
from time import mktime
import os
import subprocess
import sys
import time

import libvirt
import paramiko

cfg = dict()

ISO_PATH = "/home/jenkins/workspace/deploy_cluster/iso/"
DEFAULT_DIST = "ubuntu"
DEFAULT_PUB_SUBNET = "testing-network_pub"
DEFAULT_AMD_SUBNET = "testing-network_adm"
LIBVIRT_IMAGES_PATH = "/var/lib/libvirt/images/"
VM_TEMPLATE_XML_PATH = "/home/jenkins/workspace/build_test_vm/"
VM_TEMPLATE_NAME = "template"
TEST_LOGIN = "tester"
TEST_PASSWORD = "test"

iso_images = {
    "ubuntu": ISO_PATH + "ubuntu-14.04.2-server-amd64.iso",
    "centos": ISO_PATH + "CentOS-6.6-x86_64-minimal.iso"
}

SYSPREP_OPS_ENABLED = [
    "abrt-data",
    "bash-history",
    "blkid-tab",
    "crash-data",
    "cron-spool",
    "dhcp-client-state",
    "dhcp-server-state",
    "dovecot-data",
    "logfiles",
    "machine-id",
    "mail-spool",
    "net-hostname",
    "net-hwaddr",
    "pacct-log",
    "package-manager-cache",
    "pam-data",
    "puppet-data-log",
    "rh-subscription-manager",
    "rhn-systemid",
    "rpm-db",
    "samba-db-log",
    "script",
    "smolt-uuid",
    "ssh-userdir",
    "sssd-db-log",
    "tmp-files",
    "udev-persistent-net",
    "utmp",
    "yum-uuid",
    "customize",
    "lvm-uuids"]

APT_PACKAGES_PREINSTALL = [
    "vlan",
    "git",
    "build-essential",
    "libssl-dev",
    "libffi-dev",
    "python-dev",
    "libxml2-dev",
    "libxslt1-dev",
    "libpq-dev",
    "python-pip"
]

YUM_PACKAGES_PREINSTALL = []

NETWORK_SETUP_CMDS = [
    "sudo vconfig add eth1 101",
    "sudo ifconfig eth1 up",
    "sudo ifconfig eth1.101 inet 192.168.0.254/24 up",
]

RALLY_CMDS = [
    "git clone https://github.com/openstack/rally rally-dist",
    "~/rally-dist/install_rally.sh"
]

TEMPEST_CMDS = [
    "git clone https://github.com/openstack/rally rally-dist",
    "~/rally-dist/install_rally.sh"
]

REMOTE_FAILURE_TOKENS_LIST = [
    "Failed",
    "failed",
    "Failure",
    "HTTP 401"
]


try:
    vconn = libvirt.open("qemu:///system")
except:
    print ("\nERROR: libvirt is inaccessible!")
    sys.exit(1)


def check_args(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        spec = getargspec(f)
        none_args = []
        args_values = dict(zip(spec.args, args))
        for arg_name in args_values.keys():
            if not args_values[arg_name]:
                none_args.append(arg_name)
        if none_args:
            for arg_name in none_args:
                print "ERROR: {0} is not defined".format(arg_name)
            print "exiting..."
            exit(1)
        return f(*args, **kwargs)

    return decorated


def make_now_timestr():
    return str(mktime(
        datetime.now().timetuple())).split(".")[0]


def shell_cmd(cmdlist, stdin=None, stdout=None, stderr=subprocess.PIPE,
              ignore_exceptions=False):
    try:
        proc = subprocess.Popen(
            cmdlist,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            bufsize=1
        )
        proc.wait()
        result = {}
        if proc.returncode > 0:
            message = "Error: " + proc.stderr.read() if proc.stderr \
                else "command returned {0}, something went wrong.".format(
                    proc.returncode)
            raise Exception(message)
        if stdin:
            result["stdin"] = proc.stdin
        if stdout:
            result["stdout"] = proc.stdout
        if stderr:
            result["stderr"] = proc.stderr
    except Exception as e:
        if not ignore_exceptions:
            raise e
    return result


@check_args
def sftp_move(ip, login, password, filelist, remote_dir, local_dir,
              upload=False):
    paramiko.util.log_to_file("paramiko_sftp.log")
    transport = paramiko.Transport((ip, 22))
    transport.connect(username=login, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)
    if upload:
        for filename in filelist:
            print "{0}/{2} --> {1}/{2}".format(
                local_dir, remote_dir, filename)
            sftp.put(local_dir + "/" + filename, remote_dir + "/" + filename)
    else:
        for filename in filelist:
            sftp.get(remote_dir + "/" + filename, local_dir + "/" + filename)
    sftp.close()
    transport.close()


# FIXME: we assume NOPASSWD clause in destination's sudoers file
def perform_ssh_cmds(ip, login, password, cmds=None, filename=None,
                     sudo_password=None, echo_remote_output=False,
                     sleep=None, fail_on_errors=False):
    if not cmds and not filename:
        print("ERROR: Neither commands list nor file provided, aborting...")
        sys.exit(1)
    if filename:
        with open(filename, "r") as fin:
            content = fin.readlines()
            cmds = content.split("\n")
    paramiko.util.log_to_file("paramiko_ssh.log")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip,
                   username=login,
                   password=password)
    try:
        for cmd in cmds:
            if sleep:
                time.sleep(sleep)
            try:
                stdin, stdout, stderr = client.exec_command(cmd)
                result = stdout.read()
                result_err = stderr.read()
                if fail_on_errors:
                    for token in REMOTE_FAILURE_TOKENS_LIST:
                        if token in result_err:
                            raise Exception("Observed '{0}' in remote output, exiting.".format(token))
                print "sent command: {0}".format(cmd)
                if echo_remote_output:
                    if result:
                        print "result:\n{0}".format(result)
                    if result_err:
                        print "stderr:\n{0}".format(result_err)
            except Exception as e:
                print e
                sys.exit(1)
    finally:
        client.close()


def cleanup_vm(name, storage_pool="default", undefine=False):
    try:
        shell_cmd(["virsh", "destroy", name], ignore_exceptions=True)
        if undefine:
            shell_cmd(["virsh", "undefine", name], ignore_exceptions=True)
        shell_cmd(["virsh", "vol-delete", "--pool", storage_pool,
                   name + ".img"], ignore_exceptions=True)
    except Exception as e:
        print e
        sys.exit(1)


def show_vnc_console(name):
    result = shell_cmd(["virsh", "domdisplay", name],
                       stdout=subprocess.PIPE)
    print "{0}'s VNC console at: {1}".format(
        name,
        result["stdout"].read())


def volume_create(name, disk_size, storage_pool):
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
        pool = vconn.storagePoolLookupByName(storage_pool)
    except:
        print("\nERROR: libvirt`s storage pool '{0}' is not accessible!"
              .format(storage_pool))
        sys.exit(1)

    volume = vol_template.format(vol_name=name,
                                 vol_size=disk_size)

    try:
        vol_object = pool.createXML(volume)
    except:
        print("\nERROR: unable to create volume '{0}'!"
              .format(name))
        sys.exit(1)
    print("Created volume from XML:\n\n{0}".format(volume))
    return vol_object


@check_args
def create_vm(name, cpu_count, ram_amount, disk_size, storage_pool,
              pub_subnet, iso_path):
    vol_obj = volume_create(name, disk_size, storage_pool)

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
      <address type='pci' domain='0x0000' bus='0x00'
               slot='0x08' function='0x0'/>
    </controller>
    <controller type='pci' index='0' model='pci-root'>
      <alias name='pci.0'/>
    </controller>
    <controller type='ide' index='0'>
      <alias name='ide0'/>
      <address type='pci' domain='0x0000' bus='0x00'
               slot='0x01' function='0x1'/>
    </controller>
    <interface type='network'>
      <source network='{public_net}'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00'
               slot='0x03' function='0x0'/>
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
      <address type='pci' domain='0x0000' bus='0x00'
               slot='0x02' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <alias name='balloon0'/>
      <address type='pci' domain='0x0000' bus='0x00'
               slot='0x0a' function='0x0'/>
    </memballoon>
  </devices>
</domain>
    """

    try:
        iso = """    <disk type='file' device='cdrom'>
          <driver name='qemu' type='raw' cache='unsafe'/>
          <source file='{iso_path}'/>
          <target dev='hdb' bus='ide'/>
          <readonly/>
        </disk>""".format(iso_path=iso_path)
        xml = node_template_xml.format(
            name=name,
            vcpu=cpu_count,
            memory=ram_amount*1024,
            first_boot="cdrom",
            second_boot="hd",
            hd_volume=vol_obj.path(),
            iso=iso,
            public_net=pub_subnet
        )

        print ("Prepared XML for node:\n{0}".format(xml))
        try:
            instance = vconn.defineXML(xml)
            shell_cmd(["virsh", "start", name])
        except Exception as e:
            print (e)
            sys.exit(1)

        show_vnc_console(name)
    except Exception as e:
        print e
        cleanup_vm(name, storage_pool, undefine=True)


def replace_in_template(content, source_vm_name, template_name):
    return content.replace(
        LIBVIRT_IMAGES_PATH + source_vm_name + ".img",
        LIBVIRT_IMAGES_PATH + template_name + ".img"
    ).replace(
        "boot dev='hd'",
        "boot dev='cdrom'"
    ).replace(
        "boot dev='cdrom'",
        "boot dev='hd'", 1)


@check_args
def make_vm_template(source_vm_name, template_name,
                     destroy=True, undefine=False):
    print "======================SUMMARY======================"
    print "Using {0} VM for template".format(source_vm_name)
    print "template VM: {0}".format(template_name)
    print "Writing template VM config at {0}".format(
        VM_TEMPLATE_XML_PATH + template_name + ".xml")
    print "Writing template VM image at {0}".format(
        LIBVIRT_IMAGES_PATH + template_name + ".img")
    print "==================================================="
    try:
        shell_cmd(["virsh", "shutdown", source_vm_name])
        res = shell_cmd(["virsh", "dumpxml", source_vm_name],
                        stdout=subprocess.PIPE)
        with open(VM_TEMPLATE_XML_PATH + template_name + ".xml", "w") as fout:
            fout.write(replace_in_template(res["stdout"].read(),
                                           source_vm_name, template_name))
        shell_cmd(["cp",
                   LIBVIRT_IMAGES_PATH + source_vm_name + ".img",
                   LIBVIRT_IMAGES_PATH + template_name + ".img"])
        sysprep_cmd = ["virt-sysprep", "--operations",
                       ",".join(SYSPREP_OPS_ENABLED)]
        sysprep_cmd.extend(["-a",
                            LIBVIRT_IMAGES_PATH + template_name + ".img"])
        shell_cmd(sysprep_cmd)
        if destroy:
            cleanup_vm(source_vm_name, undefine=undefine)
    except Exception as e:
        print e
        sys.exit(1)


def attach_interface(vm_name, network_name, stop_vm=True):
    if stop_vm:
        shell_cmd(["virsh", "destroy", vm_name])
    shell_cmd(["virsh", "attach-interface", vm_name, "network",
               network_name, "--persistent"])
    shell_cmd(["virsh", "start", vm_name])


@check_args
def redefine_interface(network_name, def_file, test=None):
    shell_cmd(["virsh", "net-destroy", network_name], ignore_exceptions=True)
    shell_cmd(["virsh", "net-undefine", network_name], ignore_exceptions=True)
    shell_cmd(["virsh", "net-define", "--file", def_file])
    shell_cmd(["virsh", "net-start", network_name])


# FIXME: try to use libvirt bindings
@check_args
def clone_vm(template_name, name, pub_subnet, adm_subnet, distro, sleep, echo=False):
    # FIXME: commonalize the way of checking values such as below
    print "======================SUMMARY======================"
    print "Making clone VM named {0}".format(name)
    print "Using template definition from {0}".format(
        VM_TEMPLATE_XML_PATH + template_name + ".xml")
    print "Using template disk image from {0}".format(
        LIBVIRT_IMAGES_PATH + template_name + ".img")
    print "==================================================="

    try:
        shell_cmd(["virt-clone", "--connect", "qemu:///system",
                   "--original-xml",
                   VM_TEMPLATE_XML_PATH + template_name + ".xml",
                   "--name", name,
                   "--file",
                   LIBVIRT_IMAGES_PATH + name + ".img"])
        attach_interface(name, adm_subnet, stop_vm=False)
        show_vnc_console(name)
        ip = get_if_addr(name, pub_subnet, sleep=30)
        print "cloned VM ip: {0}".format(ip)
        if sleep:
            print "Waiting before performing ssh commands...({0} secs)".format(
                sleep)
            time.sleep(int(sleep))
        pm_command_prefix = None
        packages_preinstall_list = None
        if distro == "ubuntu":
            pm_command_prefix = "sudo apt-get -y install "
            packages_preinstall_list = APT_PACKAGES_PREINSTALL
        elif distro == "centos":
            pm_command_prefix = "sudo yum install " # TODO: check for "-y" analog
            packages_preinstall_list = YUM_PACKAGES_PREINSTALL
        perform_ssh_cmds(ip, TEST_LOGIN, TEST_PASSWORD,
                         cmds=[pm_command_prefix +
                         " ".join(packages_preinstall_list)],
                         sudo_password=TEST_PASSWORD,
                         echo_remote_output=echo)
        perform_ssh_cmds(ip, TEST_LOGIN, TEST_PASSWORD,
                         cmds=NETWORK_SETUP_CMDS,
                         sudo_password=TEST_PASSWORD,
                         echo_remote_output=echo)
    except Exception as e:
        print e
        sys.exit(1)


@check_args
def get_if_addr(name, network, sleep):
    if sleep:
        print "Waiting for VM to get up and running...({0} secs)".format(
            sleep)
        time.sleep(int(sleep))
    vm_ifaces = shell_cmd(["virsh", "domiflist", name],
                          stdout=subprocess.PIPE)["stdout"].read()
    macs = []
    for line in vm_ifaces.split('\n'):
        if network in line:
            macs.append(line.split()[4])
    ip = None
    arp_data = shell_cmd(["arp", "-e"],
                         stdout=subprocess.PIPE)["stdout"].read()
    for line in arp_data.split('\n'):
        if macs[0] in line:
            ip = line.split()[0]
    return ip


# TODO: review needed parameters
@check_args
def prepare_tool(ip, tool, fail_on_errors=False):
    # TODO: abstract login/password/etc
    if tool == "rally":
        perform_ssh_cmds(ip, TEST_LOGIN, TEST_PASSWORD,
                         cmds=RALLY_CMDS,
                         sudo_password=TEST_PASSWORD,
                         echo_remote_output=True,
                         fail_on_errors=fail_on_errors)
    elif tool == "tempest":
        perform_ssh_cmds(ip, TEST_LOGIN, TEST_PASSWORD,
                         cmds=TEMPEST_CMDS,
                         sudo_password=TEST_PASSWORD,
                         echo_remote_output=True,
                         fail_on_errors=fail_on_errors)

def preprocess_ssh_creds(ip_address, vm_name, pub_net):
    if ip_address:
        return ip_address
    else:
        ip = get_if_addr(vm_name, pub_net, sleep=None)
        return ip


def main():
    parser = ArgumentParser(description="Manage VMs")

    subparsers = parser.add_subparsers(dest="subcommand",
                                       help='sub-command help')

    parser_vm = subparsers.add_parser('vm', help='vm help')
    parser_vm.add_argument("command", type=str,
                           help="Create or remove VM",
                           metavar="command",
                           choices=["create", "remove", "getifaddr"])
    parser_vm.add_argument("--name", type=str, help="VM name",
                           metavar="NAME", dest="vm_name")
    parser_vm.add_argument("-n", "--pub-net", type=str,
                           help="Public network name",
                           metavar="PUBLIC NETWORK", dest="vm_pub_net")
    parser_vm.add_argument("-c", "--cpu", type=int, dest="vm_cpu_count",
                           help="CPU cores count", metavar="CPU")
    parser_vm.add_argument("-r", "--ram", type=int, dest="vm_ram_amount",
                           help="RAM amount", metavar="RAM")
    parser_vm.add_argument("-d", "--disk-size", dest="vm_disk_size",
                           type=int, help="Disk size (GB)",
                           metavar="DISK SIZE")
    parser_vm.add_argument("-p", "--pool", dest="vm_storage_pool",
                           help="Storage pool", metavar="STORAGE POOL")
    parser_vm.add_argument("--dist", dest="vm_linux_dist",
                           help="Linux distro", metavar="LINUX DISTRO")
    parser_vm.add_argument("--sleep", dest="vm_sleep_seconds", type=int,
                           help="Seconds to sleep before executing command")

    parser_ssh = subparsers.add_parser('ssh', help='ssh help')
    parser_ssh.add_argument("command", type=str,
                            help="Perform command(s) or prepare predefined VM",
                            metavar="command",
                            choices=["perform", "prepare", "download",
                                     "upload"])
    parser_ssh.add_argument("--vm-name", dest="ssh_vm_name", type=str,
                            help="VM name to cope with")
    parser_ssh.add_argument("--pub-net", dest="ssh_pub_net", type=str,
                            help="public network to use (to find IP, for example")
    parser_ssh.add_argument("--ip", dest="ssh_ip_address", type=str,
                            help="Remote IP address")
    parser_ssh.add_argument("--login", dest="ssh_login",
                            help="SSH login")
    parser_ssh.add_argument("--pass", dest="ssh_password",
                            help="SSH password")
    parser_ssh.add_argument("-c", "--command", dest="ssh_command",
                            help="SSH command")
    parser_ssh.add_argument("--file", dest="ssh_file",
                            help="File with commands/files-to-copy")
    parser_ssh.add_argument("--sleep", dest="ssh_sleep_seconds", type=int,
                            help="Seconds to sleep before executing command")
    parser_ssh.add_argument("--echo", dest="ssh_echo", action="store_true",
                            help="Should we echo remote commands output?")
    parser_ssh.add_argument("--fail-on-errors", dest="ssh_fail_on_errors",
                            action="store_true",
                            help="Should we fail on remote errors?")
    parser_ssh.add_argument("--tool", dest="ssh_prepare_tool", type=str,
                            help="Tool's environment to prepare",
                            metavar="TOOL", choices=["rally", "tempest"])
    parser_ssh.add_argument("--localdir", dest="ssh_local_dir", type=str,
                            metavar="DIR",
                            help="Local dir to copy remote files to")
    parser_ssh.add_argument("--remotedir", dest="ssh_remote_dir", type=str,
                            metavar="DIR",
                            help="Remote dir to copy remote files from")
    parser_ssh.add_argument("--filelist", dest="ssh_filelist", type=str,
                            metavar="FILES",
                            help="List of files to copy from remote server")

    parser_template = subparsers.add_parser('template', help='template help')
    parser_template.add_argument("command", type=str,
                                 help="Make or clone VM template",
                                 metavar="command",
                                 choices=["make", "clone"])
    parser_template.add_argument("--name", type=str, help="Template name",
                                 metavar="NAME", dest="template_name")
    parser_template.add_argument("--source", type=str,
                                 metavar="SOURCE", dest="template_source")
    parser_template.add_argument("--dest", type=str,
                                 metavar="DEST", dest="template_dest")
    parser_template.add_argument("-n", "--pub-net", type=str,
                                 help="Public network name",
                                 metavar="PUBLIC NETWORK", dest="template_pub_net")
    parser_template.add_argument("-N", "--adm-net", type=str,
                                 help="Admin network name",
                                 metavar="ADMIN NETWORK",
                                 dest="template_adm_net")
    parser_template.add_argument("--destroy-source", action="store_true",
                                 dest="template_destroy_source")
    parser_template.add_argument("--dist", dest="template_linux_dist",
                                 help="Linux distro", metavar="LINUX DISTRO")
    parser_template.add_argument("--sleep", dest="template_sleep_seconds", type=int,
                                 help="Seconds to sleep while template VM goes up and running")
    parser_template.add_argument("--echo", dest="template_echo", action="store_true",
                                 help="Should we echo remote commands output?")

    parser_network = subparsers.add_parser('network', help='network help')
    parser_network.add_argument("command", type=str,
                                help="Perform network operations",
                                metavar="command",
                                choices=["attach", "redefine"])
    parser_network.add_argument("--name", type=str, help="Network name",
                                metavar="NAME", dest="network_name")
    parser_network.add_argument("--vm", type=str, help="VM name",
                                metavar="NAME", dest="network_vm_name")
    parser_network.add_argument("--stop-vm", type=str,
                                help="Whether the VM should be stopped beforehands",
                                metavar="NAME", dest="network_stop_vm")
    parser_network.add_argument("--file", type=str,
                                help="interface definition file",
                                metavar="FILE", dest="network_definition_file")

    args = parser.parse_args()

    subparser = args.subparser
    command = args.command
    if subparser == "vm":
        pub_subnet = os.getenv("PUB_SUBNET_NAME",
                               args.vm_pub_net or DEFAULT_PUB_SUBNET)
        vm_name = os.getenv("VM_NAME", args.vm_name)
        storage_pool = os.getenv("STORAGE_POOL",
                                 args.vm_storage_pool or "default")
        if command == "create":
            create_vm(vm_name,
                      int(os.getenv("VM_CPU", args.vm_cpu_count or 4)),
                      int(os.getenv("VM_RAM", args.vm_ram_amount or 8192)),
                      int(os.getenv("VM_DISK_SIZE", args.vm_disk_size or 50)),
                      storage_pool,
                      pub_subnet,
                      os.getenv("OS_ISO",
                                iso_images[args.vm_linux_dist or DEFAULT_DIST]))
        elif command == "remove":
            cleanup_vm(vm_name, storage_pool, undefine=True)
        elif command == "getifaddr":
            ip = get_if_addr(vm_name, pub_subnet, args.vm_sleep_seconds)
            print "{0} addr: {1}".format(vm_name, ip)
    elif subparser == "template":
        pub_subnet = os.getenv("PUB_SUBNET_NAME",
                               args.template_pub_net or DEFAULT_PUB_SUBNET)
        if command == "make":
            make_vm_template(args.template_source,
                             args.template_dest or VM_TEMPLATE_NAME,
                             destroy=args.template_destroy_source)
        elif command == "clone":
            dummy_name = "testing_vm_" + make_now_timestr()
            adm_subnet = os.getenv("ADM_SUBNET_NAME", args.template_adm_net)
            clone_vm(args.template_source or VM_TEMPLATE_NAME,
                     args.template_dest or dummy_name,
                     pub_subnet,
                     adm_subnet,
                     args.template_linux_dist,
                     args.template_sleep_seconds,
                     args.template_echo)
    elif subparser == "ssh":
        eff_ip_address = preprocess_ssh_creds(args.ssh_ip_address,
                                              args.ssh_vm_name,
                                              args.ssh_pub_net)
        if command == "perform":
            cmds = None
            ssh_file = os.getenv("REMOTE_CMDS_LIST", args.ssh_file)
            if args.ssh_command and ssh_file:
                print "Use either --command or --file / env variable, not both."
                exit(1)
            if ssh_file:
                with open(ssh_file, "r") as fin:
                    cmds = fin.read().split("\n")
            elif args.ssh_command:
                cmds = [args.ssh_command]
            perform_ssh_cmds(eff_ip_address,
                             os.getenv("SSH_LOGIN",
                                       args.ssh_login or TEST_LOGIN),
                             os.getenv("SSH_PASS",
                                       args.ssh_password or TEST_PASSWORD),
                             cmds=cmds,
                             sudo_password=args.ssh_password or TEST_PASSWORD,
                             sleep=args.ssh_sleep_seconds,
                             echo_remote_output=args.ssh_echo,
                             fail_on_errors=args.ssh_fail_on_errors)
        elif command == "prepare":
            prepare_tool(eff_ip_address, args.ssh_prepare_tool,
                         args.ssh_fail_on_errors)
        elif command in ["upload", "download"]:
            files_to_copy = None
            if args.ssh_file:
                with open(ssh_file, "r") as fin:
                    files_to_copy = fin.readlines().split("\n")
            elif args.ssh_filelist:
                files_to_copy = args.ssh_filelist.split(",")
            upload = command == "upload"
            sftp_move(eff_ip_address,
                      os.getenv("SSH_LOGIN",
                                args.ssh_login or TEST_LOGIN),
                      os.getenv("SSH_PASS",
                                args.ssh_password or TEST_PASSWORD),
                      files_to_copy,
                      args.ssh_remote_dir,
                      args.ssh_local_dir,
                      upload=upload)
    elif subparser == "network":
        if command == "attach":
            attach_interface(args.network_vm_name,
                             args.network_name,
                             stop_vm=args.network_stop_vm)
        elif command == "redefine":
            redefine_interface(args.network_name,
                               args.network_definition_file)


if __name__ == '__main__':
    main()
    vconn.close()
