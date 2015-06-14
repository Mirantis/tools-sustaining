WHAT IS IT?
___________

    This script is a part of sustainig team's internal utilities repository.
    The main goal of this script is to deploy any (almost) version of Miranits
    Openstack in virtual environment and configure important parts of deployment.
    It creates networks, volumes and VMs via python libvirt bindings and manages
    the networks in order to obtain fully splitted environments with free access
    to "public" network of each environment.

    Tested on:
        * MirantisOpenstack 5.1
        * MirantisOpenstack 5.1.1
        * MirantisOpenstack 6.0
        * MirantisOpenstack 6.0.1 (development version)
        * MirantisOpenstack 6.1 (development version)

HOW TO INSTALL?
_______________

    Just download, install all requirements and it is ready.

WHAT IS REQUIRED?
_________________

    * python 2.x
    * netaddr
    * qemu-kvm
    * libvirt
    * python-libvirt
    * aria2
    * scancodes.py
    * sshpass

JENKINS JOB?
____________

    There is `config.xml` file in directory, it represents Jenkins JOB.
    Copy it to your Jenkins and use it.

HOW TO RUN IT?
______________

    From Jenkins you should dispatch new build with following variables:

    NAME - unique name of cluster
    ISO_URL - direct URL of Mirantis Openstack ISO-file or URL of torrent
    NODES_COUNT - quantity of nodes in cluster excluding Fuel-node
    ADMIN_RAM - amount of memory for Fuel-node (4096 is default and good)
    ADMIN_CPU - number of CPUs for Fuel-node
    SLAVE_RAM - amount of memory for slave-nodes in cluster (3072 and higher)
    SLAVE_CPU - number of CPUs for slave-nodes
    PREPARE_CLUSTER - if true create a cluster after Fuel installation
                      also generates networks
    NETWORK_TYPE - neutron_vlan | neutron_gre | nova
    RELEASE - base OS of cluster
    HA - high availability on/off (HA requires at least 3 controllers)

    Then you will get a status message in job's output with URL of Fuel.

NETWORKS MANAGEMENT
___________________

    By default a network with prefix size "28" will be used for "public" part
    of cluster's netwroks. This means, that the network has only 14 usable IPs
    and some of them are explicitly used:
        * 1st IP - gateway (IP on hypervisor side)
        * 2nd IP - FUEL-node IP (injected in grub-loader)
        * from 3rd till NODES_COUNT + 1 - IPs for "public" network and VIP
        * the rest of IPs - floating IPs for cluster
    Thus you should think about how many nodes you need, and 5 is a best.
    Otherwise you may get unexpected results, such as absence of floating IPs.

HOW IT WORKS?
_____________

    It's a magic.

