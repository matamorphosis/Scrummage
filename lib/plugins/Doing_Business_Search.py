#!/usr/bin/env python3
import requests, os, json, logging, plugins.common.General as General

Plugin_Name = "Doing-Business"
Concat_Plugin_Name = "doingbusiness"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "doingbusiness.org"

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

        for Query in Query_List:
            headers = General.URL_Headers(User_Agent=True, Application_JSON_CT=True)
            headers["Referer"] = f"https://www.doingbusiness.org/en/data/exploreeconomies/{Query}"
            Main_URL = f"https://wbgindicatorsqa.azure-api.net/DoingBusiness/api/GetEconomyByURL/{Query}"
            Doing_Business_Response = requests.get(Main_URL, headers=headers).text
            JSON_Response = json.loads(Doing_Business_Response)
            JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)

            if 'message' not in JSON_Response:
                Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                headers = General.URL_Headers(User_Agent=True)
                Item_URL = f"https://www.{Domain}/en/data/exploreeconomies/{Query}"
                Title = f"Doing Business | {Query}"
                Current_Doing_Business_Response = requests.get(Item_URL, headers=headers).text
                Current_Doing_Business_Response = General.Response_Filter(Current_Doing_Business_Response, f"https://www.{Domain}")

                if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache:
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Current_Doing_Business_Response, Query, The_File_Extensions["Query"])

                    if Output_file:
                        Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Economic Details", Task_ID, Concat_Plugin_Name)
                        Output_Connections.Output([Main_File, Output_file], Item_URL, Title, Concat_Plugin_Name)
                        Data_to_Cache.append(Item_URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")