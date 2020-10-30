#!/usr/bin/env python3
import os, logging, json, urllib.parse, plugins.common.General as General

Plugin_Name = "Canadian-Business"
Concat_Plugin_Name = "canadianbusiness"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "beta.canadasbusinessregistries.ca"

def Search(Query_List, Task_ID, Type, **kwargs):

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

            try:

                if Type == "CBN":
                    Main_API_URL = f'https://searchapi.mrasservice.ca/Search/api/v1/search?fq=keyword:%7B{Query}%7D+Status_State:Active&lang=en&queryaction=fieldquery&sortfield=Company_Name&sortorder=asc'
                    Response = General.Request_Handler(Main_API_URL)
                    JSON_Response = json.loads(Response)
                    Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                    Main_Output_File = General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, The_File_Extensions["Main"])

                    try:

                        if JSON_Response['count'] != 0:
                            Query = str(int(Query))
                            Main_URL = f'https://{Domain}/search/results?search=%7B{Query}%7D&status=Active'
                            Responses = General.Request_Handler(Main_URL, Filter=True, Host=f"https://{Domain}")
                            Response = Responses["Filtered"]

                            if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, General.Get_Title(Main_URL), The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections = General.Connections(Query, Plugin_Name, Domain.strip("beta."), "Company Details", Task_ID, Plugin_Name)
                                    Output_Connections.Output([Main_Output_File, Output_file], Main_URL, f"Canadian Business Number {Query}", Concat_Plugin_Name)
                                    Data_to_Cache.append(Main_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for CBN Search.")

                elif Type == "CCN":
                    Main_URL = 'https://searchapi.mrasservice.ca/Search/api/v1/search?fq=keyword:%7B' + urllib.parse.quote(Query) + '%7D+Status_State:Active&lang=en&queryaction=fieldquery&sortfield=Company_Name&sortorder=asc'
                    Response = General.Request_Handler(Main_URL)
                    JSON_Response = json.loads(Response)
                    Indented_JSON_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                    Limit = General.Get_Limit(kwargs)

                    try:
                        Main_File = General.Main_File_Create(Directory, Plugin_Name, Indented_JSON_Response, Query, The_File_Extensions["Main"])
                        Current_Step = 0
                        Output_Connections = General.Connections(Query, Plugin_Name, Domain.strip("beta."), "Company Details", Task_ID, Plugin_Name)

                        for JSON_Item in JSON_Response['docs']:

                            if JSON_Item.get('BN'):
                                CCN = JSON_Item['Company_Name']
                                CBN = JSON_Item['BN']

                                Full_CCN_URL = f'https://{Domain}/search/results?search=%7B{CBN}%7D&status=Active'

                                if Full_CCN_URL not in Cached_Data and Full_CCN_URL not in Data_to_Cache and Current_Step < int(Limit):
                                    Current_Responses = General.Request_Handler(Full_CCN_URL, Filter=True, Host=f"https://{Domain}")
                                    Current_Response = Current_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), CCN.replace(' ', '-'), The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Full_CCN_URL, f"Canadian Business Number {CBN} for Query {Query}", Concat_Plugin_Name)
                                        Data_to_Cache.append(Full_CCN_URL)

                                    else:
                                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Unable to retrieve business numbers from the JSON response.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for CCN Search.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid request type.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")