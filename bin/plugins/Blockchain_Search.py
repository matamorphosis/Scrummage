#!/usr/bin/env python3
import requests, re, plugins.common.General as General

Plugin_Name = "Blockchain"
The_File_Extension = ".html"

def Transaction_Search(Query_List, Task_ID, Type, **kwargs):
    Local_Plugin_Name = Plugin_Name + "-Transaction-Search"
    Data_to_Cache = []
    Cached_Data = []

    if "Limit" in kwargs:

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Local_Plugin_Name)
    Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        if Type == "btc" or Type == "bch":
            Query_Regex = re.search(r"[\d\w]{64}", Query)

        elif Type == "eth":
            Query_Regex = re.search(r"(0x[\d\w]{64})", Query)

        if Query_Regex:
            Main_URL = "https://www.blockchain.com/" + Type + "/tx/" + Query
            Main_Response = requests.get(Main_URL).text

            if Type == "btc":
                Address_Regex = re.findall(r"\/btc\/address\/([\d\w]{26,34})", Main_Response)

            elif Type == "bch":
                Address_Regex = re.findall(r"([\d\w]{42})", Main_Response)

            elif Type == "eth":
                Address_Regex = re.findall(r"(0x[\w\d]{40})", Main_Response)

            if Address_Regex:
                Current_Step = 0

                for Transaction in Address_Regex:
                    Query_URL = "https://www.blockchain.com/" + Type + "/address/" + Transaction

                    if Query_URL not in Cached_Data and Query_URL not in Data_to_Cache and Current_Step < Limit:
                        Transaction_Response = requests.get(Query_URL).text
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Transaction, The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Local_Plugin_Name, Query_URL, "blockchain.com", "Blockchain Address", Task_ID, General.Get_Title(Query_URL))

                        Data_to_Cache.append(Query_URL)
                        Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

def Address_Search(Query_List, Task_ID, Type, **kwargs):
    Local_Plugin_Name = Plugin_Name + "-Address-Search"
    Data_to_Cache = []
    Cached_Data = []

    if "Limit" in kwargs:

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Local_Plugin_Name)
    Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        if Type == "btc" or Type == "bch":
            Query_Regex = re.search(r"([\d\w]{26,34})", Query)

        elif Type == "eth":
            Query_Regex = re.search(r"(0x[\w\d]{40})", Query)

        if Query_Regex:
            Main_URL = "https://www.blockchain.com/" + Type + "/address/" + Query
            Main_Response = requests.get(Main_URL).text

            if Type == "btc":
                Transaction_Regex = re.findall(r"\/btc\/tx\/([\d\w]{64})", Main_Response)

            elif Type == "bch":
                Transaction_Regex = re.findall(r"([\d\w]{64})", Main_Response)

            elif Type == "eth":
                Transaction_Regex = re.findall(r"(0x[\d\w]{64})", Main_Response)

            if Transaction_Regex:
                Current_Step = 0

                for Transaction in Transaction_Regex:
                    Query_URL = "https://www.blockchain.com/" + Type + "/tx/" + Transaction

                    if Query_URL not in Cached_Data and Query_URL not in Data_to_Cache and Current_Step < Limit:
                        Transaction_Response = requests.get(Query_URL).text
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Transaction_Response, Transaction, The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Local_Plugin_Name, Query_URL, "blockchain.com", "Blockchain Transaction", Task_ID, General.Get_Title(Query_URL))

                        Data_to_Cache.append(Query_URL)
                        Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")