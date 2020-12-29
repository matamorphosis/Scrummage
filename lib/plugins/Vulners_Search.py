#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Connectors as Connectors, vulners, json, os, logging

Unacceptable_Bulletins = ["advertisement", "kitsploit"]
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Plugin_Name = "Vulners"
Domain = "vulners.com"

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:
            Configuration_Data = json.load(JSON_File)
            Vulners_Details = Configuration_Data[Plugin_Name.lower()]

            if Vulners_Details['api_key']:
                return Vulners_Details['api_key']

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load location details.")

def Search(Query_List, Task_ID, **kwargs):

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
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            vulners_api = vulners.Vulners(api_key=Load_Configuration())
            Search_Response = vulners_api.search(Query, limit=int(Limit))
            JSON_Response = json.dumps(Search_Response, indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Response, Query, The_File_Extensions["Main"])
            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Exploit", Task_ID, Plugin_Name.lower())

            for Search_Result in Search_Response:

                if Search_Result["bulletinFamily"] not in Unacceptable_Bulletins:
                    Result_Title = Search_Result["title"]
                    Result_URL = Search_Result["vhref"]
                    Search_Result_Responses = General.Request_Handler(Result_URL, Filter=True, Host=f"https://{Domain}")
                    Search_Result_Response = Search_Result_Responses["Filtered"]

                    if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Search_Result_Response, Result_Title, The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, Plugin_Name.lower())
                            Data_to_Cache.append(Result_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Skipping as bulletin type is not supported.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")