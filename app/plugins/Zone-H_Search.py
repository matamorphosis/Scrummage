#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "Zone-H"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "zone-h.org"
        self.Result_Type = "Domain Information"

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
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Domain_Regex = Common.Regex_Handler(Query, Type="Domain")

                if Domain_Regex:
                    URL = f"https://www.{self.Domain}/archive"
                    Data = {"notifier": "", "domain": Query, "filter_date_select": "", "filter": "1"}
                    Responses = Common.Request_Handler(URL, Method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                    Output_Response = Responses["Filtered"]
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Output_Response, Query, self.The_File_Extension)
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                    URL_Regex = Common.Regex_Handler(Responses["Regular"], Custom_Regex=r"\/archive\/notifier\=[\w]+")

                    if URL_Regex:
                        Output_URL = f"https://www.{self.Domain}/" + URL_Regex.group(0)
                        Title = f"{self.Plugin_Name} | {Query}"

                        if Output_URL not in Cached_Data and Output_URL not in Data_to_Cache:
                            Item_Responses = Common.Request_Handler(Output_URL, Filter=True, Host=f"https://{self.Domain}")
                            Item_Response = Item_Responses["Filtered"]
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Item_Response, Output_URL, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Output_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Output_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")