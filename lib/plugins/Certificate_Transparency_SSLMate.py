#!/usr/bin/env python3
import os, logging, json, plugins.common.General as General

Plugin_Name = "SSLMate"
The_File_Extension = ".json"
Domain = "sslmate.com"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/config/config.json')

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            SSLMate_Details = Configuration_Data[Plugin_Name.lower()]
            SSLMate_Subdomains = SSLMate_Details['search_subdomain']
            return [SSLMate_Subdomains]

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load configuration details.")

def Search(Query_List, Task_ID):

    try:
        Data_to_Cache = []
        Subdomains = Load_Configuration()
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

            if Subdomains:
                Request = f'https://api.certspotter.com/v1/issuances?domain={Query}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert'

            else:
                Request = f'https://api.certspotter.com/v1/issuances?domain={Query}&expand=dns_names&expand=issuer&expand=cert'

            Response = General.Request_Handler(Request)
            JSON_Response = json.loads(Response)

            if 'exists' not in JSON_Response:

                if JSON_Response:

                    if Request not in Cached_Data and Request not in Data_to_Cache:

                        try:

                            if General.Regex_Checker(Query, "Domain"):
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name.lower(), json.dumps(JSON_Response, indent=4, sort_keys=True), SSLMate_Regex.group(1), The_File_Extension)

                                if Output_file:
                                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Certificate", Task_ID, Plugin_Name.lower())
                                    Data_to_Cache.append(Request)

                                    if Subdomains:
                                        Output_Connections.Output([Output_file], Request, f"Subdomain Certificate Search for {Query}", Plugin_Name.lower())

                                    else:
                                        Output_Connections.Output([Output_file], Request, f"Domain Certificate Search for {Query}", Plugin_Name.lower())

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

                        except:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create file.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No response.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Query does not exist.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")