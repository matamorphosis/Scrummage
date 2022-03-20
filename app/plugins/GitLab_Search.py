#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "GitLab"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "gitlab.com"
        self.Result_Type = "Repository"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["token"])

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
            GitLab_API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:

                    if int(self.Limit) > 100:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - This plugin does not support limits over 100, setting limit to 100.")
                        self.Limit = 100

                    URL = f"https://{self.Domain}/api/v4/search?scope=projects&search={Query}&per_page={str(self.Limit)}"
                    Custom_Headers = {"PRIVATE-TOKEN": GitLab_API_Key}
                    GL_Response = Common.Request_Handler(URL, Optional_Headers=Custom_Headers)
                    JSON_Object = Common.JSON_Handler(GL_Response)
                    GL_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()

                    if len(GL_Response) > 0:
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                        for Repo in GL_Response:
                            URL = Repo["web_url"]
                            Current_GH_Repo_Responses = Common.Request_Handler(URL, Filter=True, Host=f"https://{self.Domain}")
                            Filtered_Response = Current_GH_Repo_Responses["Filtered"]
                            Title = f"{self.Plugin_Name} | {URL}"

                            if URL not in Cached_Data and URL not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, URL, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(URL)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                except Exception as e:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to complete task - {str(e)}")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")