#!/usr/bin/env python3
import json, os, logging, plugins.common.General as General

Plugin_Name = "Threat-Crowd"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "threatcrowd.org"

def Search(Query_List, Task_ID, Type):

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

            if Type == "Email":

                if General.Regex_Checker(Query, Type):
                    Local_Plugin_Name = Plugin_Name + "-" + Type
                    URL = f"https://www.threatcrowd.org/searchApi/v2/email/report/?email={Query}"
                    Response = General.Request_Handler(URL)
                    JSON_Response = json.loads(Response)

                    if int(JSON_Response.get("response_code")) != 0:
                        JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                        Permalink = JSON_Response.get("permalink")
                        Permalink_Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                        Permalink_Response = Permalink_Responses["Filtered"]
                        Title = "Threat Crowd | " + General.Get_Title_Requests_Module(Permalink).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, The_File_Extensions["Query"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Account", Task_ID, Local_Plugin_Name.lower())

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Permalink, Title, Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Provided query returned no results.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match query to email regular expression.")

            elif Type == "Domain":

                if General.Regex_Checker(Query, Type):
                    Local_Plugin_Name = Plugin_Name + "-" + Type
                    URL = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={Query}"
                    Response = General.Request_Handler(URL)
                    JSON_Response = json.loads(Response)

                    if int(JSON_Response.get("response_code")) != 0:
                        JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                        Permalink = JSON_Response.get("permalink")
                        Permalink_Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                        Permalink_Response = Permalink_Responses["Filtered"]
                        Title = "Threat Crowd | " + General.Get_Title_Requests_Module(Permalink).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, The_File_Extensions["Query"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Domain Information", Task_ID, Local_Plugin_Name.lower())
                        
                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Permalink, Title, Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Provided query returned no results.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match query to domain regular expression.")

            elif Type == "IP Address":

                if General.Regex_Checker(Query, "IP"):
                    Local_Plugin_Name = Plugin_Name + "-" + Type
                    URL = f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={Query}"
                    Response = General.Request_Handler(URL)
                    JSON_Response = json.loads(Response)

                    if int(JSON_Response.get("response_code")) != 0:
                        JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                        Permalink = JSON_Response.get("permalink")
                        Permalink_Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                        Permalink_Response = Permalink_Responses["Filtered"]
                        Title = "Threat Crowd | " + General.Get_Title_Requests_Module(Permalink).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                        Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, The_File_Extensions["Query"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Domain Information", Task_ID, Local_Plugin_Name.lower())
                        
                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Permalink, Title, Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Provided query returned no results.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match query to IP address regular expression.")

            elif Type == "AV":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                URL = f"https://www.threatcrowd.org/searchApi/v2/antivirus/report/?antivirus={Query}"
                Response = General.Request_Handler(URL)
                JSON_Response = json.loads(Response)

                if int(JSON_Response.get("response_code")) != 0:
                    JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                    Permalink = JSON_Response.get("permalink")
                    Permalink_Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                    Permalink_Response = Permalink_Responses["Filtered"]
                    Title = "Threat Crowd | " + General.Get_Title_Requests_Module(Permalink).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, The_File_Extensions["Query"])
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Virus", Task_ID, Local_Plugin_Name.lower())
                    
                    if Output_file:
                        Output_Connections.Output([Main_File, Output_file], Permalink, Title, Plugin_Name.lower())
                        Data_to_Cache.append(URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Provided query returned no results.")

            elif Type == "Virus Report":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                URL = f"https://www.threatcrowd.org/searchApi/v2/file/report/?resource={Query}"
                Response = General.Request_Handler(URL)
                JSON_Response = json.loads(Response)

                if int(JSON_Response.get("response_code")) != 0:
                    JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                    Permalink = JSON_Response.get("permalink")
                    Permalink_Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                    Permalink_Response = Permalink_Responses["Filtered"]
                    Title = "Threat Crowd | " + General.Get_Title_Requests_Module(Permalink).replace(" | Threatcrowd.org Open Source Threat Intelligence", "")
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Permalink_Response, Query, The_File_Extensions["Query"])
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Virus Report", Task_ID, Local_Plugin_Name.lower())
                    
                    if Output_file:
                        Output_Connections.Output([Main_File, Output_file], Permalink, Title, Plugin_Name.lower())
                        Data_to_Cache.append(URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Provided query returned no results.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")