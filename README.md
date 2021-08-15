# Scrummage  
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)  

<p align="center">
  <img width="172" height="203" src="/app/static/images/main.png">
</p>

**VERSION 3.6**
- Code efficiency enhancements and bug fixes for plugins.
- Significant UI/UX enhancements.
- Organisation specific settings and configurations, allowing for predefined searches based on your organisation and it's users.
- Due to the above change, if you are upgrading from version 3.4, a major update has been made to the config.json file. In the installation directory, there is a file called "3.6_Upgrade.py", please copy your config.json file to this directory and run the script to update it to the latest standard. Running it will create a file called "config_new.json", please keep a backup of your old config.json file, and then rename the "config_new.json" file to "config.json" and move it to the config directory.
- A new plugin to search GitHub repositories..
- Please note versions 3.3 - 3.6 entail a major overhaul of a lot of backend and frontend code for improved efficiency. Please don't hesitate to reach out about any code stability issues.
  
Scrummage is an OSINT tool that centralises search functionality from powerful, yet simple OSINT sites. This project draws inspiration mainly from two other projects, including:  
- The [Scumblr](https://github.com/Netflix-Skunkworks/Scumblr) project, which while is now deprecated, inspired this concept.
- The [OSINT Framework](https://osintframework.com/) project, which is a visualisation tool, depicting a range of sites that can be used to search for a variety of things.

While at first glance the web application may not look all that different when compared to Scumblr, the copious amounts of plugins this tool comes with is mainly what makes this project unique, where the provided Python/Flask web application is just a simple, lightweight, and scalable way of providing users with the ability to manage large pools of results. The other main benefit this projects brags is a much simpler installation process, which is kept up to date, compared to Scumblr which is now deprecated. 

Any feedback is welcome.

**FOR INSTRUCTIONS REFER TO THE [WIKI](https://github.com/matamorphosis/Scrummage/wiki)**

# An Overview of the Web Application

**Some of the Many Available Scrummage Plugins**  
* Blockchain Search
* Domain Fuzzer
* Twitter Scraper
* Instagram Search
* Have I Been Pwned Search
* Ahmia Darkweb Search
* IP Stack Search
* Threat Crowd Search
* Yandex and Naver Search
* Vkontakte Search
* Vulners Search
* Built With Search
* YouTube Search
* Many more... Refer to the wiki page [here](https://github.com/matamorphosis/Scrummage/wiki/The-Long-List-of-Tasks) for the full list.

---

**Dashboard**  
The dashboard is the home screen which the application directs a user to when they log in. It provides a high-level chart which shows the amount of each results based on their result type. It does this for each kind of finding. However, if a graph doesn’t load, this is most likely due to none of the results being in that category, I.e if there are no closed results, no graph will appear under “Overview of Closed Results”.  

![Dashboard](/installation/images_dark_theme/Dashboard.png)


**Events**  
The events page shows anything that changes within the web application, from logins, to failed login attempts, to any actions performed against a task. This assists with understanding what has recently been happening in the web app, and can assist in matters such as detecting brute-force login attempts or tracking down who altered a task.  
  
*Note: This page only loads the latest 1000 events, for optimisation of the web application.*  

![Events](/installation/images_dark_theme/Events.png)


**Results**  
The results page, simply shows results that have been created by a task. The results table shows the basic metadata of the result, but also provides a “Details” button which can be used to investigate the result further. As mentioned all results have some kind of output file, if a result is a link the file will be a copy of the HTML of the page. Furthermore screenshot functionality is provided to assist in keeping a photographic record of a result. Both the output and screenshot file will be deleted if the result is deleted.  
  
*Note: This page only loads the latest 1000 results, for optimisation of the web application.*  

![Results](/installation/images_dark_theme/Results.png)

For optimisation purposes, the results table only displays some of the general information regarding a result, to investigate a result further, the user should use the Details button. The details page allows the user to view the soft copy of the result's link and provides the ability for a user to generate a screenshot.  
  
![Results](/installation/images_dark_theme/Result_Details1.png)

**Tasks**  
The tasks page shows all created task, and provides the ability for the user to run each task.
This page doesn’t have a limit on tasks; however, don’t go crazy creating tasks, you can always add a list to a task, rather than having the same task created multiple times for one search. So really you shouldn’t have any more than 50 tasks.
Tasks have caching and logging for each which can be found in the “protected/output” directory under the tasks name, ex. Google Search is called “google”. If you need to remove the cache, you can edit/delete the appropriate cache file.
  
![Tasks](/installation/images_dark_theme/Tasks.png)

All the plugins are open-source, free to individuals, just like the rest of the code. Furthermore, feel free to use the pre-existing libraries used in other plugins. If you are creating or editting a plugin, make sure to understand that when you run it for the first time, the web app may reload to reload the python cache. This is normal.

**Account Settings**  
This page changes according to the user's privileges, if a user is an admin, they have the ability to change their password as well as other user's passwords, they can block and unblock users, demote and promote users' privileges, and of course create new users and delete existing users.  
Additionally users with administrative privileges can check and edit input, output, and core configuration of the tool.  
The account page looks as per below for administrative users:  

![Account](/installation/images_dark_theme/Account.png)

The account page looks as per below for non-administrative users:

![AccountLP](/installation/images_dark_theme/Account_Low_Priv.png)

**Developer Information**  
***Contributions Welcome!!***  
We welcome and encourage you to contribute to this project through creation of new plugins. If you are insterested please refer to the plugin development guide [here](https://github.com/matamorphosis/Scrummage/wiki/Plugin-Development-Guide), this will give you a run through of how to develop a Scrummage plugin, using the custom libraries provided.