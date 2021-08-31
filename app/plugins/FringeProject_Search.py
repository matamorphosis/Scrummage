#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type):
        self.Plugin_Name = "FringeProject"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "fringeproject.com"
        self.Type = Type

    def Search(self):

        try:
            Data_to_Cache = []
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

                if self.Type == "IP":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        URL = f"https://{self.Domain}/search?q={Query}"
                        Responses = Common.Request_Handler(URL, Filter=True, Host=f"https://{self.Domain}")
                        Response = Responses["Filtered"]
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Response, Query, self.The_File_Extension)
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "IP Address Information", self.Task_ID, self.Plugin_Name.lower())

                        if "This data is Not on the Map yet!" not in Response and Query not in Cached_Data and Query not in Data_to_Cache:
                            Title = f"{self.Plugin_Name} {self.Type} | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Query)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

                elif self.Type == "Domain":

                    if Common.Regex_Handler(Query, Type=self.Type):
                        URL = f"https://{self.Domain}/search?q={Query}"
                        Responses = Common.Request_Handler(URL, Filter=True, Host=f"https://{self.Domain}")
                        Response = Responses["Filtered"]
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Response, Query, self.The_File_Extension)
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Domain Information", self.Task_ID, self.Plugin_Name.lower())

                        if "This data is Not on the Map yet!" not in Response and Query not in Cached_Data and Query not in Data_to_Cache:
                            Title = f"{self.Plugin_Name} {self.Type} | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Title, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Query)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")