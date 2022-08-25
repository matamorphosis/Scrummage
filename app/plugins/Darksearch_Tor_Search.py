#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Darksearch"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".json"
        self.Domain: str = "darksearch.io"
        self.Result_Type: str = "Darkweb Link"
        self.Limit = General.Get_Limit(Limit)
        self.Pagination_Size = 20

    def Search(self):

        try:
            self.Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            self.Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            self.Cached_Data = self.Cached_Data_Object.Get_Cache()

            def Call_API_and_Output(self, Page=1, Custom_Limit=10):

                if type(Custom_Limit) == int:
                    Current_Limit = Custom_Limit

                else:
                    Current_Limit = self.Limit
                
                URL = f"https://{self.Domain}/api/search?query={self.Query}&page={str(Page)}"
                Response = Common.Request_Handler(url=URL)
                JSON_Object = Common.JSON_Handler(Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Output_Connections = General.Connections(self.Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if JSON_Response.get('data'):
                    Current_Step = 0

                    for Item in JSON_Response['data']:
                        Darksearch_URL = Item['link']
                        Title = f"{self.Plugin_Name} | {Item['title']}"

                        if Darksearch_URL not in self.Cached_Data and Darksearch_URL not in self.Data_to_Cache and Current_Step < int(Current_Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, self.Query, self.Plugin_Name, JSON_Output_Response, Darksearch_URL, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Output_file], Darksearch_URL, Title, self.Plugin_Name.lower())
                                self.Data_to_Cache.append(Darksearch_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1
                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            for Query in self.Query_List:
                self.Query = Query

                if self.Limit <= self.Pagination_Size:
                    Call_API_and_Output(self)

                else:
                    Current_Page = 1
                    Tally = 0

                    while Tally < self.Limit:
                        Difference = self.Limit - Tally

                        if Difference < 20: 
                            Call_API_and_Output(self, Page=Current_Page, Custom_Limit=Difference)

                        else:
                            Call_API_and_Output(self, Page=Current_Page)

                        Current_Page += 1
                        Tally += 20
                
            self.Cached_Data_Object.Write_Cache(self.Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")