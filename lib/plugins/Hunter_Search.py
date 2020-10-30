#!/usr/bin/env python3
import logging, os, json, plugins.common.General as General
from pyhunter import PyHunter

Plugin_Name = "Hunter"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "hunter.io"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Hunter_Details = Configuration_Data[Plugin_Name.lower()]

            if Hunter_Details['api_key']:
                return Hunter_Details['api_key']

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
        Shodan_API_Key = Load_Configuration()
        API_Session = PyHunter(Shodan_API_Key)
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            try:

                if Type == "Domain":

                    if General.Regex_Checker(Query, "Domain"):
                        Local_Plugin_Name = Plugin_Name + "-Domain"
                        API_Response = API_Session.domain_search(Query)
                        JSON_Output_Response = json.dumps(API_Response, indent=4, sort_keys=True)

                        if API_Response["domain"] and API_Response['emails']:
                            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Account", Task_ID, Plugin_Name.lower())
                            Current_Step = 0

                            for Hunter_Item in API_Response["emails"]:
                                Current_Email_Address = Hunter_Item["value"]
                                Current_Hunter_Item_Host = f"https://{Domain}/verify/{Current_Email_Address}"
                                Current_Hunter_Item_Responses = General.Request_Handler(Current_Hunter_Item_Host, Filter=True, Host=f"https://{Domain}")
                                Filtered_Response = Current_Hunter_Item_Responses["Filtered"]
                                Title = "Hunter | " + Current_Email_Address

                                if Current_Email_Address not in Cached_Data and Current_Email_Address not in Data_to_Cache and Current_Step < int(Limit):
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Filtered_Response, Current_Hunter_Item_Host, The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Current_Hunter_Item_Host, Title, Plugin_Name.lower())
                                        Data_to_Cache.append(Current_Email_Address)

                                    else:
                                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                elif Type == "Email":

                    if General.Regex_Checker(Query, "Email"):
                        Local_Plugin_Name = Plugin_Name + "-Email"
                        API_Response = API_Session.email_verifier(Query)
                        JSON_Output_Response = json.dumps(API_Response, indent=4, sort_keys=True)

                        if API_Response["email"] and API_Response['sources']:
                            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Account Source", Task_ID, Plugin_Name.lower())
                            Current_Step = 0

                            for Hunter_Item in API_Response["sources"]:
                                Current_Hunter_Item_Host = Hunter_Item["uri"]
                                Current_Hunter_Item_Domain = Hunter_Item["domain"]

                                if 'http://' in Current_Hunter_Item_Host:
                                    Current_Hunter_Item_Responses = General.Request_Handler(Current_Hunter_Item_Host, Filter=True, Host=f"http://{Current_Hunter_Item_Domain}")
                                    Filtered_Response = Current_Hunter_Item_Responses["Filtered"]

                                elif 'https://' in Current_Hunter_Item_Host:
                                    Current_Hunter_Item_Responses = General.Request_Handler(Current_Hunter_Item_Host, Filter=True, Host=f"https://{Current_Hunter_Item_Domain}")
                                    Filtered_Response = Current_Hunter_Item_Responses["Filtered"]

                                else:
                                    Filtered_Response = General.Request_Handler(Current_Hunter_Item_Host)

                                Title = "Hunter | " + Current_Hunter_Item_Host

                                if Current_Hunter_Item_Host not in Cached_Data and Current_Hunter_Item_Host not in Data_to_Cache and Current_Step < int(Limit):
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Filtered_Response, Current_Hunter_Item_Host, The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Current_Hunter_Item_Host, Title, Plugin_Name.lower())
                                        Data_to_Cache.append(Current_Hunter_Item_Host)

                                    else:
                                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

            except Exception as e:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to complete task - {str(e)}")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")