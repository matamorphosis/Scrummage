#!/usr/bin/env python3
from bs4 import BeautifulSoup
import re, requests, plugins.common.General as General

Plugin_Name = "PhishTank"
The_File_Extension = ".html"
Scrape_Regex_URL = re.compile("https?\:\/\/(www\.)?([-a-zA-Z0-9:%._\+#=]{2,256})(\.[a-z]{2,6}\b([-a-zA-Z0-9:%_\+.#?&//=]*))")

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if "Limit" in kwargs:

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Plugin_Name)
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        Pull_URL = "https://www.phishtank.com/target_search.php?target_id=" + Query + "&valid=y&active=All&Search=Search"
        Content = requests.get(Pull_URL).text
        soup = BeautifulSoup(Content, features="lxml")
        tds = soup.findAll('td')
        Links = []

        for td in tds:
            link = td.find('a')

            if link and 'phish_detail.php?phish_id=' in link.attrs['href']:
                Full_Link = "https://www.phishtank.com/" + link.attrs['href']
                Links.append(Full_Link)

        Current_Step = 0

        for Link in Links:
            Current_Content = requests.get(Link).text
            Current_Soup = BeautifulSoup(Current_Content, features="lxml")
            Spans = Current_Soup.find('span', {"style": "word-wrap:break-word;"})
            Current_Link = Spans.string

            if Current_Link:
                Phish_Site_Response = requests.get(Current_Link).text
                Output_file_query = Query.replace(" ", "-")
                Output_file = General.Create_Query_Results_Output_File(Directory, Output_file_query, Plugin_Name, Phish_Site_Response, Link.replace("https://www.phishtank.com/phish_detail.php?phish_id=", ""), The_File_Extension)

                if Output_file:

                    if Current_Link not in Cached_Data and Current_Link not in Data_to_Cache and Current_Step < int(Limit):
                        General.Connections(Output_file, Query, Plugin_Name, Current_Link, "phishtank.com", "Phishing", Task_ID, General.Get_Title(Current_Link))
                        Data_to_Cache.append(Current_Link)
                        Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")