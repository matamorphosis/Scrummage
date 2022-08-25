#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "CRT"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".html"
        self.Domain: str = "crt.sh"
        self.Result_Type: str = "Certificate Details"

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                CRT_Regex = Common.Regex_Handler(Query, Type="Domain")

                if CRT_Regex:
                    Request = f"https://{self.Domain}/?q={Query}"
                    Responses = Common.Request_Handler(url=Request, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://{self.Domain}")
                    Response = Responses["Regular"]
                    Filtered_Response = Responses["Filtered"]

                    if "<TD class=\"outer\"><I>None found</I></TD>" not in Response:

                        if Request not in Cached_Data and Request not in Data_to_Cache:

                            try:

                                if CRT_Regex:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name.lower(), Filtered_Response, CRT_Regex.group(1), self.The_File_Extension)

                                    if Output_file:
                                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                                        Output_Connections.Output([Output_file], Request, f"Subdomain Certificate Search for {Query}", self.Plugin_Name.lower())
                                        Data_to_Cache.append(Request)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

                            except:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create file.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query does not exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")