[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# Installation
**PLEASE FOLLOW CAREFULLY AS THERE IS INFORMATION PRINTED IN THE TERMINAL THAT WILL NEED TO BE RETAINED**

**This tool currently supports Debian, RHEL, and SUSE based Linux distributions.**  
**Ubuntu versions over 18.04 are recommended. Ubuntu 20.04 is ideal.**

1. Clone this repository to the location where you want to run the web application.  
```console
user@linux:~$ git clone https://github.com/matamorphosis/Scrummage
```
2. Navigate to the installation directory.
```console
user@linux:~$ cd Scrummage/installation
```
3. Run the install.sh bash script with root privileges, to install all necessary dependencies. As part of this script, it will install all python dependencies in the **"python_requirements.txt"** file and run the **"Create_Tables.py"** script to create all necessary tables in the back-end database. If you want to change the default username and database, which are both set to “scrummage” by default, change the following lines in the "install.sh" script:  
```console
DATABASE="scrummage"  
USER="scrummage"  
```
Furthermore, by default, an environment variable called "FLASK_ENV" is set to "development" as this variable is used by the web application to understand which environment it is running in. If the server is production change this variable to "production". To do this change the below line in the "install.sh" script:  
```console
FLASK_ENVIRONMENT="development"
```
Command to run:
```console
user@linux:/<PATH-TO-SCRUMMAGE>/installation$ sudo bash install.sh
```

4. When the script finishes, it should **print out the username and database it has created; furthermore, a randomly generated password will also be printed to the screen**. While the script creates a new config.json file, located in the lib/plugins/common/configuration/ directory, please retain this information. Provide the details under **"postgresql"**. If you would like to create a new user, use the **"Create_User.py"** script located in the installation directory. The command is as follows:
```console
user@linux:/<PATH-TO-SCRUMMAGE>/installation$ python3 Create_User.py --username/-u Username --password/-p Password --admin/-a [True | False] --blocked/-b [True | False]
```
5. Next, you will either need to provide certificates **or** generate a self-signed certificate to use. In either case, you will need to create a directory called "certs" in the root Scrummage directory:
```console
user@linux:/<PATH-TO-SCRUMMAGE>/installation$ cd ../
user@linux:/<PATH-TO-SCRUMMAGE>$ mkdir certs && cd certs
```
6. After which, you will then need to either provide a .key and .crt file to that directory **or** create the certificates with the command below:
```console
user@linux:/<PATH-TO-SCRUMMAGE>/certs$ openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
```
7. Next, navigate to "/lib/plugins/common/config", and verify the web application details are correct under "web-app". Ensure the certificates are set correctly. Using the path "../certs/*FILE*":
*Please replace [vim/nano/gedit/leafpad] with your text editor of choice.*
```
user@linux:/<PATH-TO-SCRUMMAGE>/lib/plugins/common/config$ [vim/emacs/nano/gedit/leafpad] config.json
```
```
"web-app": {
    "debug": false,
    "host": "127.0.0.1",
    "port": 5000,
    "certificate-file": "../certs/certificate.crt",
    "key-file": "../certs/privateKey.key",
    "api-secret": "",
    "api-validity-minutes": 60,
    "api-max-calls": 10,
    "api-period-in-seconds": 60
},
```
8. Next, ensure the path of both Google Chrome and Chromedriver are valid, without these installed and listed in the config.json file, screenshot functionality won't work. Please also ensure the version of your Chromedriver is in line with your current version of Google Chrome.
```
"google-chrome": {
    "application-path": "/usr/bin/google-chrome",
    "chromedriver-path": "/usr/bin/chromedriver"
},
```
If you are facing ongoing issues with the screenshot functionality, please refer to the "Screenshot Troubleshooting" wiki page [here](https://github.com/matamorphosis/Scrummage/wiki/Screenshot-Troubleshooting) for troubleshooting steps, including a new automated troubleshooting tool.

9. Lastly, navigate to the parent directory and then to the bin directory and start the server. You should be able to access it on https://[HOST]:[PORT], [HOST] and [PORT] should match the JSON attributes above.
```console
user@linux:~$ cd /<PATH-TO-SCRUMMAGE>/lib
user@linux:/<PATH-TO-SCRUMMAGE>/lib$ python3 Scrummage.py
```

# Tasks and APIs  
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/The-Long-List-of-Tasks

# Output Alert Options  
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Output-Options

# Setting up Your First Task
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Getting-Started-after-Installation
