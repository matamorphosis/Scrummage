#!/usr/bin/env python3
import plugins.common.General as General, re, os, logging

The_File_Extension = ".html"
Plugin_Name = "BSB"
Domain = "bsbnumbers.com"

def Search(Query_List, Task_ID):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Plugin_Name.lower())
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Plugin_Name.lower())
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)

        for Query in Query_List:
            BSB_Search_URL = f"https://www.{Domain}/{Query}.html"
            Responses = General.Request_Handler(BSB_Search_URL, Filter=True, Host=f"https://www.{Domain}")
            Response = Responses["Filtered"]
            Error_Regex = re.search(r"Correct\sthe\sfollowing\serrors", Response)
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "BSB Details", Task_ID, Plugin_Name.lower())

            if not Error_Regex:

                if BSB_Search_URL not in Cached_Data and BSB_Search_URL not in Data_to_Cache:
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, Query, The_File_Extension)

                    if Output_file:
                        Output_Connections.Output([Output_file], BSB_Search_URL, General.Get_Title(BSB_Search_URL), Plugin_Name.lower())
                        Data_to_Cache.append(BSB_Search_URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Query returned error, probably does not exist.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")