#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Cloud Storage"
        self.Concat_Plugin_Name = "cloudstorage"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "osint.sh"
        self.Limit = General.Get_Limit(Limit)
        self.Pagination_Size = 20
        self.Result_Regex = r"\<tr\>\s+\<td.+\s+.*\s+.*\s+.*\s+.*\s+.*\s+\<a\shref\=\"([^\"]+)\".*\s+.*\s+.*File\sName.*\s+([^\s]+)"

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Concat_Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Main_URL = f'https://{self.Domain}/buckets/'
                Data = {"keyword": Query, "ext": ""}
                Responses = Common.Request_Handler(Main_URL, Method="POST", Data=Data, Filter=True, Host=f"https://{self.Domain}")
                Response = Responses["Regular"]
                Filtered_Response = Responses["Filtered"]
                Regex = Common.Regex_Handler(Response, Custom_Regex=self.Result_Regex, Findall=True)

                if Regex:
                    Current_Step = 0

                    for Current_URL, File in Regex:

                        if "amazon" in Current_URL:
                            Title = f"AWS S3 Bucket | {File}"
                            self.Result_Type = "Cloud Storage - AWS S3"

                        else:
                            Title = f"Azure Blob Storage | {File}"
                            self.Result_Type = "Cloud Storage - Azure Blob"

                        if Current_URL not in Cached_Data and Current_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Title, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Output_file], Current_URL, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Current_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression for provided query.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")