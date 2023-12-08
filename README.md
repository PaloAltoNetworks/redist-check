# ![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/palo.ico?raw=true) redist-check
This tool empowers you to effortlessly determine the PAN-OS Version and Content-Version running on your Palo Alto Networks Next Generation Firewalls and Panorama devices. The primary objective is to ensure that your devices operate on a PAN-OS and Content version unaffected by the expiration of root and default certificates on December 31st, 2023.  For further details, please refer to these links below:

### [PAN-OS Root and Default Certificate Expiration on December 31, 2023](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008Vp5CAE)
### [Emergency Update Required - PAN-OS Root and Default Certificate Expiration](https://live.paloaltonetworks.com/t5/customer-advisories/emergency-update-required-pan-os-root-and-default-certificate/ta-p/564672)

Before we dive in, let's go over the prerequisites for using this tool. First, make sure you're running Python version 3.x or greater on the host you will be using to run this tool. Second, create a text file containing the IP addresses of your PANOS Next Generation Firewalls and Panorama devices. Save this file in the same location where you'll run the Self Impact Discovery Tool.  Below is an Example:

```
192.168.1.1
10.1.1.1
172.16.1.1
```
Any text editor will do as long as you save it in basic text format.  If there are any errors in the file, (ie extra carraige returns, invalid IP's) the tool will tell you and skip them.  Do not use FQDN's.  IP Addresses only.

## Step 1:

Download the tool from this site by clicking on the Green Button in the Upper Right-Hand corner labeled "Code." Next, click on "Download ZIP." This action will download everything you need to proceed to the following steps.

https://github.com/PaloAltoNetworks/redist-check/blob/main

## Step 2:

Once downloaded to a folder of your choice, extract the file into that folder. Open a terminal window or CLI on your platform, navigate to the folder where you extracted the tool, and run the following command:

```console
pip3 install -r requirements.txt
```
## or

```console
pip install -r requirements.txt
```

## Note for Windows Users:

If you are running Microsoft Windows 10, you may need to run the following commands as well:

```console
python3 -m pip install --upgrade --user urllib3
python3 -m pip install
```
## or
```console
python -m pip install --upgrade --user urllib3
python -m pip install
```
## Step 3

After installing the requirements, type the following command:
```console
python3 redist-check.py -h

usage: redist-check.py [-h] [-x] [-w [W]] [-o] [-c]

Usage Examples: 

	python3 redist-check.py -x

	python3 redist-check.py -xw

	python3 redist-check.py -xow

	python3 redist-check.py -cxow

	python3 redist-check.py -xw yourfile.html

	python3 redist-check.py -xow yourfile.html

optional arguments:
  -h, --help  show this help message and exit
  -x          Optional - Disable Links Pop-Up
  -w [W]      Optional - Create WebPage from output.  If no file is specified after '-w', then 'output.html' will be used
  -o          Requires '-w' - Open Results in Web Browser
  -c          Writes CSV for each Scenario (5 total)

```

This will display usage examples and different argument options available for this tool:

'-x' argument will suppress the Pop-Up Links for the KB and Instructions at the beginning.

'-w' argument will create an HTML file of the results.  You can specify an HTML filename of your choice if desired.

'-o' argument will open the HTML file in your browser at completion.

'-c' argument will create 5 csv files at completion.(supported.csv, unsupported.csv, os.csv, content.csv, all.csv)

### These arguments are optional and not required.

## Step 4

Run the following command. If you wish to use any of the argument options mentioned earlier, please add those to your command:

```
python3 redist-check.py
```
## or
```
python redist-check.py
```
You'll be prompted to enter the name of the text file you created earlier and your credentials. Ensure you use credentials with API access rights. MFA credentials will not work with this tool. Use a common local service account; superuser rights are not necessary—readonly-superuser will work.

Once the tool finishes running, you'll see results with different colors. Green indicates no action is needed, yellow means action is required based on the scenarios explained in the links on this GitRepo, and red means both actions need to be taken.

Example:

![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/example.png?raw=true)


Additionally, there's a webpage in the tool you can access in the same folder. The file is called PANOS_Recommend.html. Open this file with your chosen browser, and a page will appear that you can use to check any other PAN-OS Version you may be running. This webpage is designed for Scenario 1 only.  Below is a screenshot of the web page:


![alt text](https://github.com/PaloAltoNetworks/redist-check/blob/main/webpage_example.png?raw=true)
