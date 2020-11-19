#!/usr/bin/env python3
import logging, os, re, time, plugins.common.General as General

Plugin_Name = "Username-Search"
Concat_Plugin_Name = "usernamesearch"
The_File_Extension = ".html"
Domain = "usersearch.org"

def Search(Query_List, Task_ID, **kwargs):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Concat_Plugin_Name)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Concat_Plugin_Name)
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            if Query_List.index(Query) != 0:
                time.sleep(5)
                
            Main_URL = f"https://{Domain}/results_normal.php"
            body = {"ran": "", "username": Query}
            Responses = General.Request_Handler(Main_URL, Method="POST", Data=body, Filter=True, Host=f"https://{Domain}", Optional_Headers={"Content-Type": "application/x-www-form-urlencoded"})
            Response = Responses["Regular"]
            Filtered_Response = Responses["Filtered"]
            Main_File = General.Main_File_Create(Directory, Plugin_Name, Filtered_Response, Query, The_File_Extension)
            Link_Regex = re.findall(r"\<a\sclass\=\"pretty-button results-button\"\shref\=\"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%_\+~#=\.\/\?]+)\"\starget\=\"\_blank\"\>View Profile\<\/a\>", Response)
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Account", Task_ID, Concat_Plugin_Name)

            if Link_Regex:
                Current_Step = 0

                for Item_URL, WWW in Link_Regex:
                    Responses = General.Request_Handler(Item_URL, Filter=True, Host=f"https://{Domain}")
                    Response = Responses["Filtered"]

                    if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, Item_URL, The_File_Extension)

                        if Output_file:
                            Title = f"Username Search | {Item_URL}"
                            Output_Connections.Output([Main_File, Output_file], Item_URL, Title, Concat_Plugin_Name)
                            Data_to_Cache.append(Item_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        Current_Step += 1

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")