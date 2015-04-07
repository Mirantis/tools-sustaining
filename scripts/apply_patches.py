#!/usr/bin/env python
import sys
import json
import os
import subprocess

#subprocess.Popen (["ssh", "127.0.0.1", 'patch --dry-run -Ntbp0'], stdin=file,stdout=log, stderr=log)

CONFIG_FILE = "patches.list"
cfg = dict()
logfile = "patch_apply.log"
dry_run = True

def cat_file_via_pipe(file, host):
    patch={
        True:"patch --dry-run -d / -Ntbp0",
        False:"patch -d / -Ntbp0"
    }
    PIPE=subprocess.PIPE
    try:
        fp=open(file,'r')
    except Exception as e:
        msg="Error opening file {0}: {1}\n".format(file, e.args[1])
        print (msg)
        LOG(msg)
        return False
    cmdline=["ssh", host, patch[dry_run]+reverse]
    print (cmdline)
    pp=subprocess.Popen(cmdline, stdin=fp, stdout=log, stderr=log)
    pp.wait()
    fp.close()
    if pp.returncode != 0:
        print ("Something went wrong, see {0} for infomation".format(logfile))
        return False
    return True

def read_config():
    global cfg
    try:
        file = open(CONFIG_FILE, 'r')
        cfg = json.load(file)
        file.close()
    except:
        print ("Couldn't load config-file")
        os.exit(1)

def apply_patches():
    patches = cfg['patches']
    if reverse != "": patches.reverse()
    for node in cfg['nodes']:
        for patch in patches:
            LOG("\n>>>>>>>>>START of PATCHING {0} with {1} (dry-run:{2})\n\n".format(
                                                                        node,patch,dry_run))
            retval=cat_file_via_pipe(patch, node)
            if retval is False:
                msg="Unable to apply patch {0} to {1} (dry-run:{2})\n".format(patch, node, dry_run)
            else:
                msg="Successfuly patched {0} to {1} (dry-run:{2})\n".format(patch, node, dry_run)
            LOG(msg)
            print (msg)
            LOG("\n<<<<<<<<<END of PATCHING {0} with {1} (dry_run:{2})\n".format(node,patch,dry_run))

def LOG(str):
    log.write(str)
    log.flush()

def main():
    global log
    global dry_run
    global reverse
    reverse = ""
    try:
        log=open(logfile, 'w', 0)
    except:
        os.exit(1)
    for cmd in sys.argv[1:]:
        if '--apply' in cmd: dry_run = False
        if '--reverse' in cmd: reverse=" -R"

    print ("To apply patches use --apply command line option, otherwise no changes will be made.\nUse --reverse to revert patches.")

    read_config()
    apply_patches()
    log.close()

if __name__ == "__main__": main()
