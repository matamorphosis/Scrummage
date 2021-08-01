#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging, pytumblr

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "Tumblr"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "tumblr.com"
        self.Result_Type = "Social Media - Page"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["consumer_key", "consumer_secret", "oauth_token", "oauth_secret"])

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
            Tumblr_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                API_Client = pytumblr.TumblrRestClient(Tumblr_Details[0], Tumblr_Details[1], Tumblr_Details[2], Tumblr_Details[3])
                Response = API_Client.blog_info(Query)
                JSON_Output_Response = Common.JSON_Handler(Response).Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if "blog" in Response and "url" in Response.get("blog"):
                    Link = Response["blog"]["url"]
                    Responses = Common.Request_Handler(Link, Filter=True, Host=f"https://www.{self.Domain}")
                    Filtered_Response = Responses["Filtered"]

                    if Response["blog"].get("title"):
                        Title = "Tumblr | " + str(Response["blog"]["title"])

                    else:
                        Title = "Tumblr | " + General.Get_Title(Link, Requests=True)

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Link, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")