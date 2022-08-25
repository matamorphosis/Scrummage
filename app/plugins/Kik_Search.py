#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging, pytumblr

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "Kik"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension: str = ".html"
        self.Domain: str = "kik.me"
        self.Result_Type: str = "Social Media - Person"

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
                Main_URL = f"http://{self.Domain}/{Query}"
                Responses = Common.Request_Handler(url=Main_URL, Filter=True, Host=f"https://www.{self.Domain}")
                Response = Responses["Regular"]
                Filtered_Response = Responses["Filtered"]
                Kik_Item_Regex = Common.Regex_Handler(Response, Custom_Regex=rf"\<h1\sclass\=\"display\-name\"\>(.+)\<\/h1>\s+\<h2\sclass\=\"username\"\>{Query}\<\/h2\>")

                if Kik_Item_Regex and Kik_Item_Regex.group(1) != " ":
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                    Title = f"{self.Plugin_Name} | {Kik_Item_Regex.group(1)}"

                    if Main_URL not in Cached_Data and Main_URL not in Data_to_Cache:
                        Output_file = General.Main_File_Create(Directory, self.Plugin_Name, Filtered_Response, Query, self.The_File_Extension)

                        if Output_file:
                            Output_Connections.Output([Output_file], Main_URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Main_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query didn't match regex pattern.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")