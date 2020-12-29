#!/usr/bin/env python3
import plugins.common.General as General, json, logging, os, plugins.common.Connectors as Connectors

Plugin_Name = "Pinterest"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "pinterest.com"

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:
            Configuration_Data = json.load(JSON_File)
            Pinterest_Details = Configuration_Data[Plugin_Name.lower()]

            if Pinterest_Details['oauth_token']:
                return Pinterest_Details['oauth_token']

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load location details.")

def Search(Query_List, Task_ID, Type, **kwargs):

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

            if Type == "pin":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                Request_URL = f"https://api.{Domain}/v1/pins/{Query}/?access_token=" + Load_Configuration() + "&fields=id%2Clink%2Cnote%2Curl%2Ccreated_at%2Cmedia%2Coriginal_link%2Cmetadata%2Ccounts%2Ccolor%2Cboard%2Cattribution"
                Search_Response = General.Request_Handler(Request_URL)
                Search_Response = json.loads(Search_Response)

                if Search_Response.get('message') != "You have exceeded your rate limit. Try again later.":
                    JSON_Response = json.dumps(Search_Response, indent=4, sort_keys=True)
                    Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Response, Query, The_File_Extensions["Main"])
                    Result_Title = "Pinterest | " + Search_Response["data"]["metadata"]["link"]["title"]
                    Result_URL = Search_Response["data"]["url"]
                    Search_Result_Response = General.Request_Handler(Result_URL)

                    if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Search_Result_Response, Result_Title, The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Media", Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, Plugin_Name.lower())
                            Data_to_Cache.append(Result_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            elif Type == "board":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                Request_URL = "https://api.pinterest.com/v1/boards/" + Query + "/pins/?access_token=" + Load_Configuration() + "&fields=id%2Clink%2Cnote%2Curl%2Coriginal_link%2Cmetadata%2Cmedia%2Cimage%2Ccreator%2Ccreated_at%2Ccounts%2Ccolor%2Cboard%2Cattribution&limit=" + str(Limit) + ""
                Search_Response = General.Request_Handler(Request_URL)
                Search_Response = json.loads(Search_Response)

                if Search_Response.get('message') != "You have exceeded your rate limit. Try again later.":
                    JSON_Response = json.dumps(Search_Response, indent=4, sort_keys=True)
                    Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Response, Query, The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, "pinterest.com", "Social Media - Page", Task_ID, Local_Plugin_Name.lower())
                    Current_Step = 0

                    for Response in Search_Response["data"]:
                        Result_Title = "Pinterest | " + Response["note"]
                        Result_URL = Response["url"]
                        Search_Result_Response = General.Request_Handler(Result_URL)

                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Search_Result_Response, Result_Title, The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, Plugin_Name.lower())
                                Data_to_Cache.append(Result_URL)
                                Current_Step += 1

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")