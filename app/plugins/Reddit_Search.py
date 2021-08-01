#!/usr/bin/env python3
import os, praw, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Reddit"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "reddit.com"
        self.Result_Type = "Forum"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["client_id", "client_secret", "user_agent", "username", "password", "subreddits"])

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
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            Reddit_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Results = []

                try:
                    Reddit_Connection = praw.Reddit(client_id=Reddit_Details[0], client_secret=Reddit_Details[1], user_agent=Reddit_Details[2], username=Reddit_Details[3], password=Reddit_Details[4])
                    All_Subreddits = Reddit_Connection.subreddit(Reddit_Details[5])

                    for Subreddit in All_Subreddits.search(Query, limit=self.Limit):
                        Results.append(Subreddit.url)

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to get results. Are you connected to the internet?")

                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                for Result in Results:

                    if Result not in Cached_Data and Result not in Data_to_Cache and not any(Result.endswith(Extension) for Extension in [".jpg", ".png", ".jpeg"]):

                        try:
                            Reddit_Responses = Common.Request_Handler(Result, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                            Reddit_Response = Reddit_Responses["Filtered"]
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Reddit_Response, Result, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Output_file], Result, General.Get_Title(Result), self.Plugin_Name.lower())
                                Data_to_Cache.append(Result)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        except:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create file.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")