# ![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/palo.ico?raw=true) redist-check
Tool to check for PANOS Devices with Certificates that will expire on 12-31-23
This tool is for checking PANOS or Panorama and Content Versions of Palo Alto NGFW’s and will inform on which NGFW’s need a PANOS Upgrade or Content Version Update.  You’ll need to create a text file with your PANOS NGFW IP Addresses as such:

192.168.1.1  
10.1.1.1  
172.16.1.1  
Etc…..  


There is a requirements.txt file and you’ll need to run this command in a terminal Window of your host in order to use redist-check.py:

pip3 install -r requirements.txt

Example:

![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/example.png?raw=true)

The results are color-coded.  If the result is green, then no action needs to be taken.  If the result is in yellow, then one of the actions needs to be taken.  If the result is in red, then both actions need to be taken.

The 'web' folder also has a web page with lots of info for getting a recommended release for your affected PANOS Version with links on instructions, HowTo's and TAC Support Info.
