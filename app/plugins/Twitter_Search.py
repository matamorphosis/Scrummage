#!/usr/bin/python3
import os, logging, tweepy, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Twitter"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "twitter.com"
        self.Result_Type: str = "Social Media - Page"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["consumer_key", "consumer_secret", "access_key", "access_secret"])

        if Result:
            return Result

        else:
            return None

    def General_Pull(self, Handle, Directory, API):

        try:
            Data_to_Cache: list = list()
            JSON_Response: list = list()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()
            Latest_Tweets = API.user_timeline(screen_name=Handle, count=self.Limit)

            for Tweet in Latest_Tweets:

                try:
                    JSON_Response.append({
                        'id': Tweet.id,
                        'text': Tweet.text,
                        'author_name': Tweet.user.screen_name,
                        'url': Tweet.entities['urls'][0]["expanded_url"]
                    })

                except:
                    JSON_Response.append({
                        'id': Tweet.id,
                        'text': Tweet.text,
                        'author_name': Tweet.user.screen_name
                    })

            JSON_Output = Common.JSON_Handler(JSON_Response).Dump_JSON()
            Output_Connections = General.Connections(Handle, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output, Handle, self.The_File_Extensions["Main"])

            for JSON_Item in JSON_Response:

                if all(Item in JSON_Item for Item in ['id', 'url', 'text']):
                    Link = JSON_Item['url']

                    if Link not in Cached_Data and Link not in Data_to_Cache:
                        Title = f"{self.Plugin_Name} | {JSON_Item['text']}"
                        Item_Responses = Common.Request_Handler(url=Link, Filter=True, Host=f"https://{self.Domain}")
                        Item_Response = Item_Responses["Filtered"]

                        Output_file = General.Create_Query_Results_Output_File(Directory, Handle, self.Plugin_Name, Item_Response, str(JSON_Item['id']), self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Link, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Link)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Output file not returned.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Insufficient parameters provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

    def Search(self):

        try:
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Twitter_Credentials = self.Load_Configuration()

            for Query in self.Query_List:

                try:
                    Authentication = tweepy.OAuthHandler(Twitter_Credentials[0], Twitter_Credentials[1])
                    Authentication.set_access_token(Twitter_Credentials[2], Twitter_Credentials[3])
                    API = tweepy.API(Authentication)
                    self.General_Pull(Query, Directory, API)

                except:
                    logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to get results. Are you connected to the internet?")

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")