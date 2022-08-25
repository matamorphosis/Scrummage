#!/usr/bin/env python3
import os, logging, wikipedia, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Wikipedia"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".html"
        self.Domain: str = "wikipedia.org"
        self.Result_Type: str = "Wiki Page"
        self.Limit = General.Get_Limit(Limit)

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
                Results = wikipedia.search(Query)
                Current_Step = 0
                
                for Result in Results:

                    try:
                        Page = wikipedia.page(Result)
                        Full_URL = Page.url
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                        if Full_URL not in Cached_Data and Full_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Item_Responses = Common.Request_Handler(url=Full_URL, Filter=True, Host=f"https://www.{self.Domain}")
                            Item_Response = Item_Responses["Filtered"]
                            Title = f"{self.Plugin_Name} | {Page.title}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Item_Response, Title, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Output_file], Full_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Full_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                    except:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Page doesn't exist, skipping.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")