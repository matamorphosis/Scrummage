#!/usr/bin/env python3
import plugins.common.General as General, json, os, logging, plugins.common.Connectors as Connectors

The_File_Extension = ".json"
Plugin_Name = "IPStack"
Domain = "ipstack.com"
headers = General.URL_Headers(User_Agent=True)

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:
            Configuration_Data = json.load(JSON_File)
            IP_Stack_Details = Configuration_Data[Plugin_Name.lower()]

            if IP_Stack_Details['api_key']:
                return IP_Stack_Details['api_key']

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load location details.")

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

            if General.Regex_Checker(Query, "IP"):
                API_Key = Load_Configuration()
                Search_Response = General.Request_Handler(f"http://api.{Domain}/{Query}?access_key={API_Key}")
                JSON_Response = json.loads(Search_Response)
                JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "IP Address Information", Task_ID, Plugin_Name.lower())

                if Query not in Cached_Data and Query not in Data_to_Cache:
                    Result_URL = f"https://{Domain}/?{Query}"
                    Title = f"IP Stack | {Query}"
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Output_Response, Title, The_File_Extension)

                    if Output_file:
                        Output_Connections.Output([Output_file], Result_URL, Title, Plugin_Name.lower())
                        Data_to_Cache.append(Result_URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")