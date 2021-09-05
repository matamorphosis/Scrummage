#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "TorWhois"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "torwhois.com"
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
                Search_URL = f"https://{self.Domain}"
                Data = {"input": Query}
                Responses = Common.Request_Handler(Search_URL, Method="POST", Data=Data, Filter=True, Host=Search_URL)
                Response = Responses["Filtered"]
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if "Invalid .ONION domain" not in Response:
                    Output_URL = f"{Search_URL}?{Query}"

                    if Output_URL not in Cached_Data and Output_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Query, self.The_File_Extension)

                        if Output_file:
                            Output_Connections.Output([Output_file], Output_URL, f"Tor Whois | {Query}", self.Plugin_Name.lower())
                            Data_to_Cache.append(Output_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query returned error, probably does not exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")