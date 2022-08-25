#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging, pytumblr
from requests_oauthlib import OAuth1Session

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "Tumblr"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "tumblr.com"
        self.Result_Type: str = "Social Media - Page"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["consumer_key", "consumer_secret", "oauth_token", "oauth_secret"])

        if Result:
            return Result

        else:
            return None

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
            Tumblr_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Tumblr = OAuth1Session(Tumblr_Details[0], client_secret=Tumblr_Details[1], callback_uri='http://www.tumblr.com/dashboard')
                OAuth_Details = Tumblr.fetch_request_token("http://www.tumblr.com/oauth/request_token")
                API_Client = pytumblr.TumblrRestClient(Tumblr_Details[0], Tumblr_Details[1], OAuth_Details["oauth_token"], OAuth_Details["oauth_token_secret"])
                Response = API_Client.blog_info(Query)
                JSON_Output_Response = Common.JSON_Handler(Response).Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if "blog" in Response and "url" in Response.get("blog"):
                    Link = Response["blog"]["url"]
                    Responses = Common.Request_Handler(url=Link, Filter=True, Host=f"https://www.{self.Domain}")
                    Filtered_Response = Responses["Filtered"]

                    if Response["blog"].get("title"):
                        Title = f"{self.Plugin_Name} | {str(Response['blog']['title'])}"

                    else:
                        Title = f"{self.Plugin_Name} | {General.Get_Title(Link, Requests=True)}"

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Filtered_Response, Link, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")