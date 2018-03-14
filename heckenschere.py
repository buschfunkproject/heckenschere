#!/usr/bin/python

import crypt
import os
import re
from subprocess import check_output

#config_file = "boot/buschfunk.txt"
#if_mesh_file = "/tmp/etc/network/interfaces.d/mesh"
#hostname_file = "/tmp/hostname"
#shadow_file = "/tmp/shadow"

config_file = "/boot/buschfunk.txt"
if_mesh_file = "/etc/network/interfaces.d/mesh"
dns_file = "/etc/dnsmasq.d/ap_ns"
hostname_file = "/etc/hostname"
shadow_file = "/etc/shadow"

dry_run = True

def get_pid(name):
    try:
        return map(int,check_output(["pidof",name]).split())
    except:
        return []


def get_dns_config(ip):
    dns = """
address=/busch.funk/%s

    """ % (ip)
    return dns

def get_mesh_config(ip, channel = "3", essid = "LOEWE_NICER_AdHoc"):
    mesh = """
auto wlan0
iface wlan0 inet static
address %s
netmask 255.255.255.0
wireless-channel %s
wireless-essid %s
wireless-mode ad-hoc
    """ % (ip, channel, essid)
    return mesh

def write_config(config_file, cfg):
    if not dry_run:
        with open(config_file, "w") as myfile:
            myfile.write(cfg)

def is_current_mesh_config(ip, channel = "3", essid = "LOEWE_NICER_AdHoc"):
    with open(if_mesh_file) as myfile:
        all = myfile.read()
    return (ip in all and "channel " + channel in all and essid in all)        

def is_current_pw(pw):
    with open(shadow_file) as myfile:
        entries = myfile.readlines()

    for e in entries:
        if "pi:$6$" in e:
            hash_all = e.split(":")[1]
            salt_end = hash_all.find("$",4)
            if salt_end == -1:
                print "Error: no salt found!"
                return False
            salt = hash_all[0:salt_end+1]
            npw = crypt.crypt(pw, salt)
            return (npw == hash_all)
            
    
    return False

res = {}

with open(config_file) as myfile:
    for line in myfile:
        if "=" in line and line[0] != '#':
            name, var = line.partition("=")[::2]
            res[name.strip()] = var.strip()

print(res)

reboot = False

if res.has_key("hostname"):
    #print "Checking hostname.."
    with open(hostname_file) as myfile:
        h = myfile.read().strip()
    if h == res['hostname']:        
        pass
    else:
        print("updating hostname to " + res['hostname'])
        write_config(hostname_file, res['hostname']+"\n")        
        reboot = True
else:
    print "Error: please set a hostname in %s!!" % config_file

if res.has_key('mesh_ip'):
    if res.has_key('mesh_channel'):
        if not is_current_mesh_config(res['mesh_ip'], channel = res['mesh_channel']):
            print "updating mesh network config"
            write_config(if_mesh_file, get_mesh_config(ip = res['mesh_ip'], channel = res['mesh_channel']))
            reboot = True
    else:
        if not is_current_mesh_config(res['mesh_ip']):
            print "updating mesh network config"
            write_mesh_config(if_mesh_file, get_mesh_config(ip = res['mesh_ip']))            
            reboot = True
else:
    print "Error: please set mesh_ip in %s!!" % config_file

if res.has_key('password'):
    if not is_current_pw(res['password']):
        print("Changing password for user pi...")
        if not dry_run:
            os.system("echo 'pi:%s' | chpasswd" % res['password'])

if res.has_key('serval'):
    if res['serval'] == '1': # activate
        if get_pid('servald') == []:            
            if not dry_run:
                print("enabling serval")
                os.system("systemctl enable servald.service")
                os.system("systemctl start servald.service")
        else:
            pass
            # already activated
    else:
        if get_pid('servald') == []:
            pass
            # already deactivated
        else:            
            if not dry_run:
                print("disabling serval")
                os.system("systemctl disable servald.service")
                os.system("systemctl stop servald.service")

location = "66.5436144,25.84719730000006"
if res.has_key('location'):
    if len(res['location'].split(",")) == 2:
        location = re.sub('[\s+]', '', res['location'])

with open("/tmp/location.latlon.txt", "w") as gps:
    gps.write(location + "\n")


if reboot:
    print("Rebooting to apply new settings!")
    os.system("reboot")
