#!/usr/bin/env python

import build_cluster


CONNECT_LINE = "root@621_admin"
PSWD= "r00tme"

def test_bool(name,func):
    if func:
        print "\033[32mOK\033[00m   - "+name
    else:
        print "\033[31mOK\033[00m   - "+name

def main():

    test_bool("sshpass_admin_node",
        build_cluster.sshpass_admin_node (
            psw=PSWD,
            ssh_cmd=["ssh", CONNECT_LINE , "hostname"]
        )
    )

    test_bool("sshpass_admin_node fail exit code",
        not build_cluster.sshpass_admin_node (
            psw=PSWD,
            ssh_cmd=["ssh", CONNECT_LINE , "exit 1"]
        )
    )

    test_bool("copy_update_helper",
        build_cluster.copy_update_helper (CONNECT_LINE, PSWD)
    )

# NOTE: can take to many time...
#    test_bool("do update",
#        build_cluster.do_update (CONNECT_LINE, PSWD)
#    )

if __name__ == "__main__":
    main()
