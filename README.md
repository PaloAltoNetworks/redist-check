# ![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/palo.ico?raw=true) redist-check
This tool was built to check for PANOS Devices with Certificates that will expire on 12-31-23.  The tool can check for PANOS and Content Versions of Palo Alto Networks NGFW & Panorama devices and will determine which devices need a PANOS Upgrade or Content Version Update.  You’ll need to create a text file with your PANOS NGFW and Panorama IP Addresses in it as such:
```
192.168.1.1
10.1.1.1
172.16.1.1
```
Any text editor will do as long as you save it in basic text format.  The tool does require Python Version 3.x or greater to run.  The 'PANOS_Recommend.html' file is a web page with lots of info for getting a recommended release for your affected PANOS Version with links on instructions, HowTo's and TAC Support Info.  For further details, please refer to these links below:

### [PAN-OS Root and Default Certificate Expiration on December 31, 2023](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008Vp5CAE)
### [Emergency Update Required - PAN-OS Root and Default Certificate Expiration](https://live.paloaltonetworks.com/t5/customer-advisories/emergency-update-required-pan-os-root-and-default-certificate/ta-p/564672)

## Step 1:

Download the tool from this site:  

https://github.com/PaloAltoNetworks/redist-check/blob/main

## Step 2:

There is a requirements.txt file and you’ll need to run this command in a terminal Window of your host in order to use redist-check.py.  Unpack the contents into a folder of your choice and navigate to the path of that folder via CLI and run the command below:

```console
pip3 install -r requirements.txt
```

## Step 3

Once requirements are installed, you can type 'python3 redist-check.py -h' and the following will display the Usage Examples and different argument options that can be used for this tool:

```console
python3 redist-check.py -h

usage: redist-check.py [-h] [-x] [-w [W]] [-o]

Usage Examples: 

	python3 redist-check.py

	python3 redist-check.py -x /// This one suppresses PopUp Links

	python3 redist-check.py -x -w yourfile.html -o

	python3 redist-check.py -oxw yourfile.html

	python3 redist-check.py -xw -o /// This one will use output.html by default

optional arguments:
  -h, --help  show this help message and exit
  -x          Optional - Disable Links Pop-Up
  -w [W]      Optional - Create WebPage from output.  If no file is specified after '-w', then 'output.html' will be used
  -o          Requires '-w' - Open Results in Web Browser

```

'-x' argument will suppress the Pop-Up Links for the KB and Instructions at the beginning.

'-w' argument will create an HTML file of the results.  You can specify an HTML filename of your choice if desired.

'-o' argument will open the HTML file in your browser at completion.

### All of these arguments are optional and not required.

## Step 4

Below is an example of output after running this command:

```
python3 redist-check.py
```
The results are color-coded.  If the result is green, then no action needs to be taken.  If the result is in yellow, then one of the actions needs to be taken.  If the result is in red, then both actions need to be taken.

You do not have to be superuser to run this script on your host; readonly-superuser will work.  

Example:

![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/output_example.png?raw=true)

Below is a screenshot of the web page:


![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/webpage_example.png?raw=true)
