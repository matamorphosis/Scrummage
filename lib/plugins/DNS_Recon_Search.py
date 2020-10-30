#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.checkdmarc as checkdmarc, json, os, logging

The_File_Extensions = {"Main": ".json", "Query": ".html"}
Plugin_Name = "DNS-Recon"
Concat_Plugin_Name = "dnsrecon"

def Search(Query_List, Task_ID):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Concat_Plugin_Name)
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

        try:
            DNS_Info = checkdmarc.check_domains(Query_List)

            if len(Query_List) > 1:

                for DNS_Item in DNS_Info:
                    Query = DNS_Item['base_domain']
                    Output_Dict = json.dumps(DNS_Item, indent=4, sort_keys=True)
                    Link = "https://www." + Query
                    Title = "DNS Information for " + DNS_Item['base_domain']

                    if Link not in Data_to_Cache and Link not in Cached_Data:
                        Responses = General.Request_Handler(Link, Filter=True, Host=f"https://www.{Query}")
                        Response = Responses["Filtered"]
                        Main_File = General.Main_File_Create(Directory, Plugin_Name, Output_Dict, Query, The_File_Extensions["Main"])
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, Title, The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections = General.Connections(Query, Plugin_Name, Query, "Domain Information", Task_ID, Concat_Plugin_Name)
                            Output_Connections.Output([Main_File, Output_file], Link, Title, Concat_Plugin_Name)
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

            else:
                Query = DNS_Info['base_domain']
                Output_Dict = json.dumps(DNS_Info, indent=4, sort_keys=True)
                Link = "https://www." + Query
                Title = "DNS Information for " + Query

                if Link not in Data_to_Cache and Link not in Cached_Data:
                    Responses = General.Request_Handler(Link, Filter=True, Host=f"https://www.{Query}")
                    Response = Responses["Filtered"]
                    Main_File = General.Main_File_Create(Directory, Plugin_Name, Output_Dict, Query, The_File_Extensions["Main"])
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, Title, The_File_Extensions["Query"])

                    if Output_file:
                        Output_Connections = General.Connections(Query, Plugin_Name, Query, "Domain Information", Task_ID, Concat_Plugin_Name)
                        Output_Connections.Output([Main_File, Output_file], Link, Title, Concat_Plugin_Name)
                        Data_to_Cache.append(Link)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

        except:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Error retrieving DNS details.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")