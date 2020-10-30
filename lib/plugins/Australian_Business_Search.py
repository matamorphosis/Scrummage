#!/usr/bin/env python3
import os, re, logging, plugins.common.General as General

Plugin_Name = "Australian-Business"
Concat_Plugin_Name = "australianbusiness"
The_File_Extensions = {"Main": ".html", "Query": ".html"}
Domain = "abr.business.gov.au"

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

                if Type == "ABN":
                    Main_URL = f'https://{Domain}/ABN/View?id=' + Query
                    Responses = General.Request_Handler(Main_URL, Filter=True, Host=f"https://www.{Domain}")
                    Response = Responses["Regular"]

                    try:

                        if 'Error searching ABN Lookup' not in Response:
                            Query = str(int(Query))
                            Response = Responses["Filtered"]

                            if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, General.Get_Title(Main_URL), The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)
                                    Output_Connections.Output([Output_file], Main_URL, General.Get_Title(Main_URL).strip(" | ABN Lookup"), Concat_Plugin_Name)
                                    Data_to_Cache.append(Main_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - ABN Lookup returned error.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for ABN Search.")

                elif Type == "ACN":
                    Main_URL = f'https://{Domain}/Search/Run'
                    Data = {'SearchParameters.SearchText': Query, 'SearchParameters.AllNames': 'true', 'ctl00%24ContentPagePlaceholder%24SearchBox%24MainSearchButton': 'Search'}
                    Responses = General.Request_Handler(Main_URL, Method="POST", Filter=True, Host=f"https://www.{Domain}", Data=Data)
                    Response = Responses["Regular"]
                    Filtered_Response = Responses["Filtered"]
                    Limit = General.Get_Limit(kwargs)

                    try:
                        ACN_Regex = re.search(r".*[a-zA-Z].*", Query)

                        if ACN_Regex:
                            Main_File = General.Main_File_Create(Directory, Plugin_Name, Filtered_Response, Query, The_File_Extensions["Main"])
                            Current_Step = 0
                            ABNs_Regex = re.findall(r"\<input\sid\=\"Results\_NameItems\_\d+\_\_Compressed\"\sname\=\"Results\.NameItems\[\d+\]\.Compressed\"\stype\=\"hidden\"\svalue\=\"(\d{11})\,\d{2}\s\d{3}\s\d{3}\s\d{3}\,0000000001\,Active\,active\,([\d\w\s\&\-\_\.]+)\,Current\,", Response)

                            if ABNs_Regex:
                                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Company Details", Task_ID, Plugin_Name)

                                for ABN_URL, ACN in ABNs_Regex:
                                    Full_ABN_URL = f'https://{Domain}/ABN/View?abn={ABN_URL}'

                                    if Full_ABN_URL not in Cached_Data and Full_ABN_URL not in Data_to_Cache and Current_Step < int(Limit):
                                        ACN = ACN.rstrip()
                                        Current_Responses = General.Request_Handler(Full_ABN_URL, Filter=True, Host=f"https://www.{Domain}")
                                        Current_Response = Current_Responses["Filtered"]
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, str(Current_Response), ACN.replace(' ', '-'), The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], Full_ABN_URL, General.Get_Title(Full_ABN_URL).strip(" | ABN Lookup"), Concat_Plugin_Name)
                                            Data_to_Cache.append(Full_ABN_URL)

                                        else:
                                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                        Current_Step += 1

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Response did not match regular expression.")

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Query did not match regular expression.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided for ACN Search.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid request type.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")