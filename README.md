[![Github Sponsorship](/installation/images_dark_theme/github_sponsor_btn.svg)](https://github.com/sponsors/matamorphosis)

# Scrummage  
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)  

<p align="center">
  <img width="172" height="203" src="/app/static/images/main.png">
</p>

**VERSION 3.9**
- Improved dependency management (migration to Poetry)
- Stricter type checking of variables.
- Improved anonymity of the configuration file via encryption. (Manual editing of configuration file is now difficult and it's advised to not edit the configuration file manually.)
- Code quality and security enhancements, including revamping of input validation.
  
Scrummage is an OSINT tool that centralises search functionality from a bounty of powerful, publicly-available, third-party, OSINT websites.

Scrummage provides distinct value in terms of the copious amounts of plugins this tool comes with. The provided Python/Flask web application is just a simple, lightweight, and scalable way of providing users with the ability to manage large pools of results. The installation of this tool is simple, and can be circumvented with the provided image, which will create a new instance of Scrummage when run for the first time.

Please feel free to contribute to this project, whether via reporting bugs or creating new feature requests. If you don't want to contribute to the code base, but want to get behind the Scrummage project, Sponsorship enables us to continue to improve and mature the platform. We are happy to reward our sponsors with platform support and in other ways shown on the sponsorship page. Scrummage will always remain open-source, and free of charge, as a way to give back to the global, open-source, security community. However, we recognise that learning how to use the platform, and implement it, especially in complex environments, can be challenging. This is where Sponsorship can be used to obtain that extra support.

**FOR INSTRUCTIONS REFER TO THE [WIKI](https://github.com/matamorphosis/Scrummage/wiki)**

# An Overview of the Web Application

## Some of the Many Available Scrummage Plugins  
* Blockchain Search
* Domain Fuzzer
* Twitter Scraper
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

## Dashboard
The dashboard is the home screen which the application directs a user to when they log in. It provides a high-level chart which shows the amount of each results based on their result type. It does this for each kind of finding. However, if a graph doesn’t load, this is most likely due to none of the results being in that category, I.e if there are no closed results, no graph will appear under “Closed Results by Type”.  

![Dashboard](/installation/images_dark_theme/Dashboard_Main.png)

![Dashboard](/installation/images_dark_theme/Dashboard_Tasks.png)

![Dashboard](/installation/images_dark_theme/Dashboard_Results.png)

![Dashboard](/installation/images_dark_theme/Dashboard_Events.png)


## Events
The events page shows anything that changes within the web application, from logins, to failed login attempts, to any actions performed against a task. This assists with understanding what has recently been happening in the web app, and can assist in matters such as detecting brute-force login attempts or tracking down who altered a task.  
  
*Note: This page only loads the latest 1000 events, for optimisation of the web application.*  

![Events](/installation/images_dark_theme/Events.png)


## Results
The results page, simply shows results that have been created by a task. The results table shows the basic metadata of the result, but also provides a “Details” button which can be used to investigate the result further. As mentioned all results have some kind of output file, if a result is a link the file will be a copy of the HTML of the page. Furthermore screenshot functionality is provided to assist in keeping a photographic record of a result. Both the output and screenshot file will be deleted if the result is deleted.  
  
*Note: This page only loads the latest 1000 results, for optimisation of the web application.*  

![Results](/installation/images_dark_theme/Results.png)

For optimisation purposes, the results table only displays some of the general information regarding a result, to investigate a result further, the user should use the Details button. The details page allows the user to view the soft copy of the result's link and provides the ability for a user to generate a screenshot.  
  
![Results](/installation/images_dark_theme/Result_Details1.png)

## Tasks  
The tasks page shows all created task, and provides the ability for the user to run each task.
This page doesn’t have a limit on tasks; however, don’t go crazy creating tasks, you can always add a list to a task, rather than having the same task created multiple times for one search. So really you shouldn’t have any more than 50 tasks.
Tasks have caching and logging for each which can be found in the “protected/output” directory under the tasks name, ex. Google Search is called “google”. If you need to remove the cache, you can edit/delete the appropriate cache file.
  
![Tasks](/installation/images_dark_theme/Tasks.png)

All the plugins are open-source, free to individuals, just like the rest of the code. Furthermore, feel free to use the pre-existing libraries used in other plugins. If you are creating or editting a plugin, make sure to understand that when you run it for the first time, the web app may reload to reload the python cache. This is normal.

## Account Settings
This page changes according to the user's privileges, if a user is an admin, they have the ability to change their password as well as other user's passwords, they can block and unblock users, demote and promote users' privileges, and of course create new users and delete existing users.  
Additionally users with administrative privileges can check and edit input, output, and core configuration of the tool.  
The account page looks as per below for administrative users:  

![Account](/installation/images_dark_theme/Account.png)

The account page looks as per below for non-administrative users:

![AccountLP](/installation/images_dark_theme/Account_Low_Priv.png)

## Identities
This concept was introduced in v3.6 of the Scrummage platform, this page is not to be confused with the Account Settings page. Account Settings is for managing users of the Scrummage platform itself, identities, is an entirely optional feature, where if rows are present, the information within can be used when executing tasks.  
This is the main page, depicting a table with a faux identity created for documentation purposes:  

![Identities](/installation/images_dark_theme/Identities.png)

Identities can be created one of three ways:

1. Individual creation (Use the "Create Identity" function.)
![Identities1](/installation/images_dark_theme/Identities_New.png)
2. Bulk upload of identities (Use the "Bulk Upload" function.)
![Identities1](/installation/images_dark_theme/Identities_Upload.png)
3. If you have an IDM system in place, you are welcome to onboard straight to the Scrummage database, under the `org_identities` table. This will help streamline and maintain your list of identities effectively.

****

## Developers
***Contributions Welcome!!***  
We welcome and encourage you to contribute to the Scrummage project through creation of new plugins. If you are interested please refer to the plugin development guide [here](https://github.com/matamorphosis/Scrummage/wiki/Plugin-Development-Guide), this will give you a run through of how to develop a Scrummage plugin, using the custom libraries provided.

# List of Current Monthly Sponsors

[Tines](https://www.tines.com/?utm_source=oss&utm_medium=sponsorship&utm_campaign=matamorphosis)
<p align="left">
  <img width="200" height="72" src="./installation/images_dark_theme/Tines-Sponsorship-Badge-Purple.png">
</p>
