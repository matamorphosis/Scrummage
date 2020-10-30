#!/usr/bin/env python3
import logging, os, re, plugins.common.General as General

Plugin_Name = "Windows-Store"
Concat_Plugin_Name = "windowsstore"
The_File_Extension = ".html"
Domain = "microsoft.com"

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
        Location = General.Load_Location_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            Main_URL = f"https://www.{Domain}/en-{Location}/search?q={Query}"
            Win_Store_Response = General.Request_Handler(Main_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True)
            Main_File = General.Main_File_Create(Directory, Plugin_Name, Win_Store_Response, Query, The_File_Extension)
            Win_Store_Regex = re.findall(r"\/en\-au\/p\/([\w\-]+)\/([\w\d]+)", Win_Store_Response)
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Application", Task_ID, Concat_Plugin_Name)

            if Win_Store_Regex:
                Current_Step = 0

                for Regex_Group_1, Regex_Group_2 in Win_Store_Regex:
                    Item_URL = f"https://www.microsoft.com/en-au/p/{Regex_Group_1}/{Regex_Group_2}"
                    Win_Store_Responses = General.Request_Handler(Item_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                    Win_Store_Response = Win_Store_Responses["Filtered"]
                    Title = "Windows Store | " + General.Get_Title(Item_URL)

                    if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Win_Store_Response, Regex_Group_1, The_File_Extension)

                        if Output_file:
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