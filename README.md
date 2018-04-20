# dynamic-cdn

This script automates the start or stop the servers on a simple CDN network
and updates DNS record based on servers availability.

Before running this script, check the following tutorial to setup a CDN network
in a lab environment:
https://sonusz.gitbooks.io/ece8930_lab7_lab_guide/content/

This is a simplified implementation of the Dynamic DDoS Mitigation (DDM) 
system originally implemented by Ilker. This script automates the detection of 
the reverse proxies' availability, start and stop reverse proxies, and update 
DNS records. This script does not automate any initialization setup, e.g., 
ssh-key import, install packets, setup bind, or setup reverse proxy servers. 
This script has only been tested in a lab environment with all private IPs.

Here is a link to Ilker's original implementation:
https://www.dropbox.com/s/bdxo0fau8nr0073/MitigationSystemInstructions.pdf?dl=0

