#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common, feedparser

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Craigslist"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "craigslist.org"
        self.Result_Type = "Search Result"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["city"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Craigslist_Location = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Main_URL = f"https://{Craigslist_Location.lower()}.{self.Domain}/search/sss?format=rss&query={Query}"
                Craigslist_Response = feedparser.parse(Main_URL)
                Craigslist_Items = Craigslist_Response["items"]
                Current_Step = 0

                for Item in Craigslist_Items:
                    Item_URL = Item["link"]

                    if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                        Local_Domain = f"{Craigslist_Location.lower()}.{self.Domain}"
                        Local_URL = f"https://{Local_Domain}"
                        Craigslist_Responses = Common.Request_Handler(Item_URL, Filter=True, Host=Local_URL)
                        Craigslist_Response = Craigslist_Responses["Filtered"]
                        Local_URL = f"{Local_URL}/"

                        Filename = Item_URL.replace(Local_URL, "")
                        Filename = Filename.replace(".html/", "")
                        Filename = Filename.replace(".html", "")
                        Filename = Filename.replace("/", "-")
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Craigslist_Response, Filename, self.The_File_Extension)

                        if Output_file:
                            Output_Connections = General.Connections(Query, self.Plugin_Name, Local_Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                            Output_Connections.Output([Output_file], Item_URL, General.Get_Title(Item_URL), self.Plugin_Name.lower())
                            Data_to_Cache.append(Item_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        Current_Step += 1

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f'{Common.Date()} - {self.Logging_Plugin_Name} - {e}')