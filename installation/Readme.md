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
Furthermore, by default, an environment variable called "FLASK_ENV" is set to "development" as this variable is used by the web application to understand which environment it is running in. If the server is production change this variable's value to "production". To do this change the below line in the "install.sh" script:  
```console
FLASK_ENVIRONMENT="development"
```
Command to run:
```console
user@linux:/<PATH-TO-SCRUMMAGE>/installation$ sudo bash install.sh
```

4. When the script finishes, it should **print out the username and database it has created; furthermore, a randomly generated password will also be printed to the screen**. While the script creates a new config.json file, located in the app/plugins/common/configuration/ directory, please retain this information. Provide the details under **"postgresql"**. If you would like to create a new user, use the **"Create_User.py"** script located in the installation directory. The command is as follows:
```console
user@linux:/<PATH-TO-SCRUMMAGE>/installation$ python3 Create_User.py --username/-u Username --password/-p Password --admin/-a [True | False] --blocked/-b [True | False]
```
5. If you have your own certificates that you would like to use over the default self-signed certificate, please move the .crt and .key pair to the <PATH-TO-SCRUMMAGE>/certs directory
6. Next, navigate to "/app/plugins/common/config", and verify the web application details are correct under "web-app". Ensure the certificates are set correctly. Using the path "../certs/*FILE*":
*Please replace [vim/nano/gedit/leafpad] with your text editor of choice.*
```console
user@linux:/<PATH-TO-SCRUMMAGE>/app/plugins/common/config$ [vim/emacs/nano/gedit/leafpad] config.json
```
```json
"web_app": {
  "debug": false,
  "host": "127.0.0.1",
  "port": 5000,
  "certificate_file": "../certs/certificate.crt",
  "key_file": "../certs/privateKey.key",
  "api_secret": "",
  "api_validity_minutes": 60,
  "api_max_calls": 10,
  "api_period_in_seconds": 60
},
```
7. Next, ensure the path of both Google Chrome and Chromedriver are valid, without these installed and listed in the config.json file, screenshot functionality won't work. Please also ensure the version of your Chromedriver is in line with your current version of Google Chrome.
```json
"google_chrome": {
  "application_path": "/usr/bin/google-chrome",
  "chromedriver_path": "/usr/bin/chromedriver"
},
```
If you are facing ongoing issues with the screenshot functionality, please refer to the "Screenshot Troubleshooting" wiki page [here](https://github.com/matamorphosis/Scrummage/wiki/Screenshot-Troubleshooting) for troubleshooting steps, including a new automated troubleshooting tool.

8. Next, if you need to use a proxy you need to set it up under the "proxy" section. If you are within an organisation where your device has a pre-configured system proxy, all you need to do is set "use_system_proxy" to true. Otherwise, please provide the proxy server for HTTP and HTTPS as per python's specifications.
```json
"proxy": {
  "http": "",
  "https": "",
  "use_system_proxy": false
},
```

9. Lastly, navigate to the parent directory and then to the bin directory and start the server. You should be able to access it on https://[HOST]:[PORT], [HOST] and [PORT] should match the JSON attributes above. You can authenticate using the username and password printed out from running the install.sh bash script. The username is `admin` unless in the script prior to being run.
```console
user@linux:~$ cd /<PATH-TO-SCRUMMAGE>/app
user@linux:/<PATH-TO-SCRUMMAGE>/app$ python3 Scrummage.py
```

# Tasks and APIs  
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/The-Long-List-of-Tasks

# Output Alert Options  
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Output-Options

# Setting up Your First Task
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Getting-Started-after-Installation

# Building Your First Custom Task (Developers Only)
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Plugin-Development-Guide