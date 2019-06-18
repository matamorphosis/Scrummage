#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests, re, plugins.common.General as General

Query = ""
File_Query = ""
Plugin_Name = "Windows-Store"
Concat_Plugin_Name = "windowsstore"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if "Limit" in kwargs:

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Concat_Plugin_Name)
    General.Logging(Directory, Concat_Plugin_Name)
    Location = General.Load_Location_Configuration()
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        Main_URL = "https://www.microsoft.com/en-" + Location + "/search?q=" + Query
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
        Win_Store_Response = requests.get(Main_URL, headers=headers).text
        General.Main_File_Create(Directory, Plugin_Name, Win_Store_Response, Query, The_File_Extension)
        Win_Store_Regex = re.findall(r"\/en\-au\/p\/([\w\-]+)\/([\w\d]+)", Win_Store_Response)

        if Win_Store_Regex:
            Current_Step = 0

            for Regex_Group_1, Regex_Group_2 in Win_Store_Regex:
                Item_URL = "https://www.microsoft.com/en-au/p/" + Regex_Group_1 + "/" + Regex_Group_2
                headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
                Win_Store_Response = requests.get(Item_URL, headers=headers).text

                if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache  and Current_Step < Limit::
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Win_Store_Response, Regex_Group_1, The_File_Extension)

                    if Output_file:
                        General.Connections(Output_file, Query, Plugin_Name, Item_URL, "microsoft.com", "Data Leakage", Task_ID, General.Get_Title(Item_URL))

                    Data_to_Cache.append(Item_URL)
                    Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")