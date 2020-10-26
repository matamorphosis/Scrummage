#!/usr/bin/env python3
import requests, os, logging, requests, re, plugins.common.General as General

Plugin_Name = "CRT"
The_File_Extension = ".html"
Domain = "crt.sh"

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
            SSLMate_Regex = re.search("([\w\d]+)\.[\w]{2,3}(\.[\w]{2,3})?(\.[\w]{2,3})?", Query)

            if SSLMate_Regex:
                Request = f"https://{Domain}/?q={Query}"
                Response = requests.get(Request, headers=General.URL_Headers(User_Agent=True, Accept_XML=True, Accept_Language_EN_US=True)).text
                Filtered_Response = General.Response_Filter(Response, f"https://{Domain}")

                if "<TD class=\"outer\"><I>None found</I></TD>" not in Response:

                    if Request not in Cached_Data and Request not in Data_to_Cache:

                        try:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name.lower(), Filtered_Response, SSLMate_Regex.group(1), The_File_Extension)

                            if Output_file:
                                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Certificate", Task_ID, Plugin_Name.lower())
                                Output_Connections.Output([Output_file], Request, f"Subdomain Certificate Search for {Query}", Plugin_Name.lower())
                                Data_to_Cache.append(Request)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create file.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Query does not exist.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")