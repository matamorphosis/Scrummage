#!/usr/bin/env python3
import logging, os, time, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Username"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name).replace("-Search", "")
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "usersearch.org"
        self.Result_Type = "Account"
        self.Limit = General.Get_Limit(Limit)

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name.lower())), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Query_List.index(Query) != 0:
                    time.sleep(5)
                    
                Main_URL = f"https://{self.Domain}/results_normal.php"
                body = {"ran": "", "username": Query}
                Responses = Common.Request_Handler(Main_URL, Method="POST", Data=body, Filter=True, Host=f"https://{self.Domain}", Optional_Headers={"Content-Type": "application/x-www-form-urlencoded"})
                Response = Responses["Regular"]
                Filtered_Response = Responses["Filtered"]
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Filtered_Response, Query, self.The_File_Extension)
                Link_Regex = Common.Regex_Handler(Response, Custom_Regex=r"\<a\sclass\=\"pretty-button results-button\"\shref\=\"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%_\+~#=\.\/\?]+)\"\starget\=\"\_blank\"\>View Profile\<\/a\>", Findall=True)
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if Link_Regex:
                    Current_Step = 0

                    for Item_URL, WWW in Link_Regex:
                        Responses = Common.Request_Handler(Item_URL, Filter=True, Host=f"https://{self.Domain}")
                        Response = Responses["Filtered"]

                        if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Item_URL, self.The_File_Extension)

                            if Output_file:
                                Title = f"{self.Plugin_Name} | {Item_URL}"
                                Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Item_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")