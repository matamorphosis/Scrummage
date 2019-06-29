# Scrummage
Scrummage is an OSINT tool that centralises your OSINT scans, leveraging powerful yet simple OSINT sites, drawing inspiration from the https://github.com/Netflix-Skunkworks/Scumblr project as well as the the OSINT framework, a high-level overview of a range of sites that can be used to search for a variety of things, which can be found at https://osintframework.com/ or https://github.com/lockfale/OSINT-Framework.

While at first glance the web application may not look that original when compared to Scumblr, the plugins this tool uses is what makes this project unique, the web application is mainly just a simple, lightweight, and scalable way of bringing all the results together in one simple console, built on python's flask library for simplicity and scalability.

All feedback is welcome, as this is version 1 I'm sure there will be lots to improve on.


# An Overview of the Web Application

**Some of the Available Plugins**
* Blockchain Search
* Domain Fuzzer
* Twitter Scraper
* Instagram Search
* Have I Been Pwned Search
* Many more... Refer to the installation Readme.md file for the full list.

**What's on the Horizon for Scrummage**
* Support for more crypto-currencies for the blockchain plugin
* Public record search plugins
* Torrent Site Search plugins
* Facebook and Pinterest plugins

---

**Dashboard**
The dashboard is the home screen which the application directs a user to when they log in. It provides a high-level chart which shows the amount of each results based on their result type. It does this for each kind of finding. However, if a graph doesn’t load, this is most likely due to none of the results being in that category, I.e if there are no closed results, no graph will appear under “Overview of Closed Results”.
![Dashboard](/installation/Dashboard.png)


**Events**
The events page shows anything that changes within the web application, from logins, to failed login attempts, to any actions performed against a task. This assists with understanding what has recently been happening in the web app, and can assist in matters such as detecting brute-force login attempts or tracking down who altered a task.
*Note: This page only loads the latest 1000 events, for optimisation of the web application.*
![Events](/installation/Events.png)


**Results**
The results page, simply shows results that have been created by a task. The results table shows the basic metadata of the result, but also provides a “Details” button which can be used to investigate the result further. As mentioned all results have some kind of output file, if a result is a link the file will be a copy of the HTML of the page. Furthermore screenshot functionality is provided to assist in keeping a photographic record of a result. Both the output and screenshot file will be deleted if the result is deleted.
*Note: This page only loads the latest 1000 results, for optimisation of the web application.*
![Results](/installation/Results.png)

For optimisation purposes, the results table only displays some of the general information regarding a result, to investigate a result further, the user should use the Details button. The details page allows the user to view the soft copy of the result's link and provides the ability for a user to generate a screenshot.
![Results](/installation/Result_Details1.png)

Furthermore, buttons for reviewing, inspecting and closing a result are provided to show other users where a result is at in terms of assessment. The buttons are colour coded and are coloured as the result progresses through the assessment.
![Results](/installation/Result_Details2.png)

Results are categorised into the following:
* Data Leakage
* Domain Spoof
* Phishing
* Exploit
* Blockchain Address
* Blockchain Transaction

**Tasks**
The tasks page shows all created task, and provides the ability for the user to run each task.
This page doesn’t have a limit on tasks; however, don’t go crazy creating tasks, you can always add a list to a task, rather than having the same task created multiple times for one search. So really you shouldn’t have any more than 50 tasks.
Tasks have caching and logging for each which can be found in the “protected/output” directory under the tasks name, ex. Google Search is called “google”. If you feel the need to remove the cache, you can delete the appropriate cache file.
Plugins
![Tasks](/installation/Tasks.png)

All the plugins are open-source, free to individuals, just like the rest of the code. Furthermore, feel free to use the pre-existing libraries used in other plugins. If you are creating or editting a plugin, make sure to understand that when you run it for the first time, the web app may reload to reload the python cache. This is normal.

**Developer Information**
Knock yourself out, create any plugins you like, and feel free to leverage existing libraries to help you.
Please remember that the first time you run a plugin from the web app after changing the code, or creating a new plugin, you will need to click run and then restart the web app to allow for it to generate the pycache for the plugin.
