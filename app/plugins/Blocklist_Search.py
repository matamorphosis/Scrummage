#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "Blocklist"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".html"
        self.Domain: str = "blocklist.de"
        self.Result_Type: str = "IP Address Information"

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Type="IP"):
                    URL = f"https://www.{self.Domain}/en/search.html?ip={Query}&action=search&send=start+search"
                    Response = Common.Request_Handler(url=URL)
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if "We could not found any matches about your search string" not in Response and URL not in Cached_Data and URL not in Data_to_Cache:
                        Title = f"{self.Plugin_Name} | {Common.Fang().Defang(Query)}"
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extension)

                        if Output_file:
                            Output_Connections.Output([Output_file], URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - IP Address not found in blocklist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")