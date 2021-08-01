[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# Installation
**PLEASE FOLLOW CAREFULLY AS THERE IS INFORMATION PRINTED IN THE TERMINAL THAT WILL NEED TO BE RETAINED**

**Docker automates almost the entire installation process and doesn't give you the choice of OS, Ubuntu 20.04 is the current distribution used.**  
**If you want a more in depth understanding of the installation steps, please check out the Wiki page [here](https://github.com/matamorphosis/Scrummage/blob/master/installation/Readme.md)**  
**This guide assumes you have docker installed on your system already.**

**NOTE: It is recommended that you change configuration for things like API keys, via the "Edit Inputs", "Edit Outputs", and "Edit Core" functions on the settings page.**  
**TIP: For those that are new to docker, running "docker run..." creates a new container, so all changes will be lost after the build. Use "docker attach" to not overwrite changes.**

1. If not done already, navigate to the Docker Installation directory
```console
user@linux:~$ cd Scrummage/installation/docker
```

2. Build the docker image
```console
user@linux:/<PATH-TO-SCRUMMAGE>/installation/docker$ docker build -t scrummage/latest .
```

3. Run the container and take note of the admin password. (This password is randomly and automatically generated in a secure manner, it is only displayed on the first run of the container, after which is detroyed for obvious security reasons). This password can be changed via the settings page after logging in, but this step is not required.
```console
user@linux:~$ docker run -p 5000:5000 scrummage/latest
---EXAMPLE OUTPUT---
 * Restarting PostgreSQL 12 database server
   ...done.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
This is the admin password, this will only be displayed on the first run of Scrummage:
<PASSWORD WILL BE DISPLAYED HERE>
...
-------------------
```

4. Find your docker container's IP address through a tool like ifconfig/ipconfig. Then navigate to https://<DOCKER-IP-HERE>:5000, accept the certificate, and log in with the password provided to you in the previous step.

# Tasks and APIs  
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/The-Long-List-of-Tasks

# Output Alert Options  
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Output-Options

# Setting up Your First Task
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Getting-Started-after-Installation

# Building Your First Custom Task (Developers Only)
Refer to the Wiki Page https://github.com/matamorphosis/Scrummage/wiki/Plugin-Development-Guide