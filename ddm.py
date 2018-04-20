#!/usr/bin/env python3.6
"""
This is a simplified implementation of the Dynamic DDoS Mitigation (DDM) 
system originally implemented by Ilker. This script automates the detection of 
the reverse proxies' availability, start and stop reverse proxies, and update 
DNS records. This script does not automate any initialization setup, e.g., 
ssh-key import, install packets, setup bind, or setup reverse proxy servers. 
This script has only been tested in a lab environment with all private IPs.

This script will be running on the Domain Name System (DNS) server of a 
content delivery network (CDN). Before running this script, you should have a 
working CDN with a DNS server, and several reverse proxy servers with cache 
enabled. The DNS should simply resolve the domain of the mitigation system to 
all IPs of the reverse proxy servers with a bunch of A records. You need ssh 
password-less login to all hosts running the reverse proxy virtual machines 
and the reverse proxy virtual machines them self.

Test pssh commands from the machine running this script to all the hosts and 
guest machines before proceed. Also, "VirtualBox guest additions" needs to be 
installed on the reverse proxy virtual machines for host machines to get the 
IP of the virtual machines.


Example setup:

host_username = 't1'        # This is the user name on the host machines with reverse proxy virtual machine pre-configured
guest_username = 'root'     # This is the user name on the reverse proxy virtual machine
hosts_file = '~/hosts.txt'  # All IPs of the host machines that runs reverse proxy virtual machines. One IP per line，no punctuations needed.
domain = 'ddm.lan'          # The base domain of the mitigation system. The resolved domain will be "edge.ddm.lan"
zone_file = '/etc/named/zones/db.ddm.lan'   # Zone file path
minimum_proxies = 4         # If available number of reverse proxy virtual machine is less than this value, start more VMs
maximum_proxies = 6         # If available number of reverse proxy virtual machine is more than this value, stop one VM
"""
__author__ = "Xingsi Zhong"
__credits__ = ["Ilker Ozcelik", "Prfo. Richard Brooks", "Fei Sun"]
__email__ = "xingsiz@g.clemson.edu"
__license__ = "MIT"
__updated__ = '2018-04-20'


import socket       # Validate IP format
import subprocess   # Execute bash command
import time         # Update DNS zone file serial number
import requests     # Check HTTP request timeout


host_username = 't1'        # This is the user name on the host machines with reverse proxy virtual machine pre-configured
guest_username = 'root'     # This is the user name on the reverse proxy virtual machine
hosts_file = '~/hosts.txt'  # All IPs of the host machines that runs reverse proxy virtual machines. One IP per line，no punctuations needed.
domain = 'ddm.lan'          # The base domain of the mitigation system. The resolved domain will be "edge.ddm.lan"
zone_file = '/etc/named/zones/db.ddm.lan'   # Zone file path
minimum_proxies = 2         # If available number of reverse proxy virtual machine is less than this value, start more VMs
maximum_proxies = 2         # If available number of reverse proxy virtual machine is more than this value, stop one VM

def main():
    zone = ZoneFile(domain, zone_file)
    all_hosts = read_IPs_from_file(hosts_file)
    running_guest = len(all_hosts)
    """The variable "running_guest" is used to control the number of 
    VMs to start or stop, not necessarily the real number of VMs that 
    is running now. This value will in crease by one when less than 
    required cache servers available and reduce by one when more than 
    enough cache servers are available. In many cases it is difficult 
    to know the true status of a VM and whether the command was 
    successfully delivered and executed. So, instead of precisely 
    control and trace the status of every single VM, the script send 
    command to machines in all_hosts[:running_guest] to start a VM. It 
    is OK if the host in that range already have VMs running. After 
    several rounds, either sufficient number of VMs are started,  or 
    more than enough VMs started, or all VMs are running but still not 
    having enough reverse proxies.
    
    """
    while True:
        available_guests = check_available_guests(
            check_guests_IP(all_hosts))  # Return a list of IPs of the available guests
        print(len(available_guests), 'proxy servers on line.')
        if len(available_guests) < minimum_proxies:  # Too few guests available
            print('Wake more proxy servers.')
            running_guest += 1
            running_guest = min(running_guest, len(all_hosts))
            startvm(all_hosts[:running_guest])
            time.sleep(120)                  # It takes a while to get an IP after boot
            available_guests = check_available_guests(
                check_guests_IP(all_hosts))  # Get available guests
            zone.update(available_guests)    # Update DNS
        elif len(available_guests) > maximum_proxies:  # Too much guests available
            print('Turn off one proxy server.')
            running_guest -= 1
            running_guest = max(running_guest, 0)
            stopvm(available_guests[-1:])
            time.sleep(10)
            available_guests = check_available_guests(
                check_guests_IP(all_hosts))
            zone.update(available_guests)
        time.sleep(10)


pssh_template = "pssh -l {} -h {} -t {} -P \'{}\'"


def stopvm(guest_IPs):
    # Send 'shutdown now' to guest machines in the guest_IPs list
    print('Stop proxy server at', guest_IPs)
    write_IPs_to_file(guest_IPs, 'temp_hosts')
    time_out = 30
    bash_cmd = 'shutdown now'
    cmd = pssh_template.format(guest_username, 'temp_hosts', time_out, bash_cmd)
    execute_bash(cmd)


def startvm(host_IPs):
    # Start VMs from machines in the host_IPs list
    write_IPs_to_file(host_IPs, 'temp_hosts')
    time_out = 30
    bash_cmd = 'vboxmanage startvm CentOS --type headless'
    cmd = pssh_template.format(host_username, 'temp_hosts', time_out, bash_cmd)
    execute_bash(cmd)


def check_guests_IP(host_IPs):
    # Get guest machines IP using VirtualBox GA
    write_IPs_to_file(host_IPs, 'temp_hosts')
    time_out = 15
    bash_cmd = 'vboxmanage guestproperty enumerate CentOS | grep V4/IP'
    cmd = pssh_template.format(host_username, 'temp_hosts', time_out, bash_cmd) + \
        "| grep V4/IP | awk '{print substr($5,1, length($5)-1)}'"
    return execute_bash(cmd)


def execute_bash(cmd):
    print(cmd)
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, shell=True)
    _output, error = process.communicate()
    print(_output)
    output = [line.decode("utf-8") for line in _output.splitlines()]
    return output


def check_available_guests(guest_IPs):
    # send Get requests to guests
    # Server is considered healthy if response in less than 5 seconds
    available_guests = set()
    for guest_IP in guest_IPs:
        try:
            requests.get('http://' + guest_IP, timeout=5)
            available_guests.add(guest_IP)
        except:
            pass
    return list(available_guests)


def write_IPs_to_file(IPs, file):
    with open(file, 'w') as f:
        f.writelines("%s\n" % l for l in IPs)


def read_IPs_from_file(file):
    with open(file, 'r') as f:
        lines = f.read().splitlines()
        IPs = []
        for line in lines:
            try:
                socket.inet_aton(line)  # Validate IP address
                IPs.append(line)  # Ignore \n
            except:
                continue
    return IPs


class ZoneFile():
    # This class is used to update A records in zone file 'file_path'
    def __init__(self, domain, file_path):
        self.domain = domain  # e.g. 'ddm.lan'
        self.file_path = file_path  # e.g. '/etc/named/zones/db.ddm.lan'
        self.my_IP = self.my_ip_address()
        self.zone_template = """$TTL    1200
@   IN  SOA ns.{}.    admin.{}. (
        {}  ; Serial
        120         ; Refresh
        180         ; Retry
        7200        ; Expire
        300         ; Negative Cache TTL
)

        IN  NS  ns.{}.     ; define name server - NS record
        IN  A   {}  ; define name server's IP address - A record
ns      IN  A   {}  ; define IP address of a hostname - A record

edge{}

"""

    def my_ip_address(self):
        # Get your IP by establish a connection to 8.8.8.8
        # This method only works where you have access to 8.8.8.8, otherwise change to another IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
        s.close()
        return my_ip

    def update(self, available_edges):
        # available_edges = ['192.168.10.6', '192.168.10.9']
        edge_records = '    IN  A   ' + \
            '\n        IN  A   '.join(available_edges)
        zone = self.zone_template.format(self.domain, self.domain, 
                                         int(time.time()), self.domain, 
                                         self.my_IP, self.my_IP, edge_records)
        with open(self.file_path, 'w') as f:
            f.write(zone)
        execute_bash('systemctl reload named')


if __name__ == '__main__':
    main()
