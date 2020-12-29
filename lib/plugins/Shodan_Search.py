#!/usr/bin/env python3
import logging, os, json, plugins.common.General as General, plugins.common.Connectors as Connectors
from shodan import Shodan

Plugin_Name = "Shodan"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "shodan.io"

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Shodan_Details = Configuration_Data[Plugin_Name.lower()]

            if Shodan_Details['api_key']:
                return Shodan_Details['api_key']

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
        API_Session = Shodan(Shodan_API_Key)
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            try:

                if Type == "Search":
                    Local_Plugin_Name = Plugin_Name + "-Search"

                    try:
                        API_Response = API_Session.search(Query)

                    except Exception as e:
                        logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}.")
                        break

                    JSON_Output_Response = json.dumps(API_Response, indent=4, sort_keys=True)
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Domain Information", Task_ID, Plugin_Name.lower())
                    Current_Step = 0

                    for Shodan_Item in API_Response["matches"]:
                        Shodan_Item_Module = Shodan_Item['_shodan']['module']
                        Shodan_Item_Host = ""
                        Shodan_Item_Port = 0

                        if 'http' in Shodan_Item:
                            Shodan_Item_Host = Shodan_Item['http']['host']
                            Shodan_Item_Response = Shodan_Item['http']['html']

                        elif 'ip_str' in Shodan_Item:
                            Shodan_Item_Host = Shodan_Item['ip_str']
                            Shodan_Item_Response = Shodan_Item['data']

                        if Shodan_Item_Host:

                            if 'port' in Shodan_Item_Host:

                                if int(Shodan_Item['port']) not in [80, 443]:
                                    Shodan_Item_Port = Shodan_Item['port']

                            if Shodan_Item_Port != 0:
                                Shodan_Item_URL = f"{Shodan_Item_Module}://{Shodan_Item_Host}:{str(Shodan_Item_Port)}"

                            else:
                                Shodan_Item_URL = f"{Shodan_Item_Module}://{Shodan_Item_Host}"

                            Title = "Shodan | " + str(Shodan_Item_Host)

                            if Shodan_Item_URL not in Cached_Data and Shodan_Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Shodan_Item_Response, Shodan_Item_Host, The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Shodan_Item_URL, Title, Plugin_Name.lower())
                                    Data_to_Cache.append(Shodan_Item_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                elif Type == "Host":
                    Local_Plugin_Name = Plugin_Name + "-Host"

                    try:
                        API_Response = API_Session.host(Query)

                    except Exception as e:
                        logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}.")
                        break

                    JSON_Output_Response = json.dumps(API_Response, indent=4, sort_keys=True)
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Domain Information", Task_ID, Plugin_Name.lower())
                    Shodan_URL = f"https://www.{Domain}/host/{Query}"
                    Title = "Shodan | " + Query

                    if Shodan_URL not in Cached_Data and Shodan_URL not in Data_to_Cache:
                        Shodan_Responses = General.Request_Handler(Shodan_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                        Shodan_Response = Shodan_Responses["Filtered"]
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Shodan_Response, Query, The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Shodan_URL, Title, Plugin_Name.lower())
                            Data_to_Cache.append(Shodan_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to complete task.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")