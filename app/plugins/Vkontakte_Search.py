#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Type: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Vkontakte"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "vk.com"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["access_token"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:

            def Recursive_Dict_Check(Items, Dict_to_Check):

                try:

                    for Item in Items:

                        if Item in Dict_to_Check:
                            Dict_to_Check = Dict_to_Check[Item]

                        else:
                            return False

                    return Dict_to_Check

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            VK_Access_Token = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == "User":
                    VK_Response = Common.Request_Handler(url=f"https://api.{self.Domain}/method/users.search?v=5.52&access_token={VK_Access_Token}&fields=verified, blacklisted, sex, bdate, city, country, home_town, photo_50, photo_100, photo_200_orig, photo_200, photo_400_orig, photo_max, photo_max_orig, online, lists, self.Domain, has_mobile, contacts, site, education, universities, schools, status, last_seen, followers_count, common_count, counters, occupation, nickname, relatives, relation, personal, connections, exports, wall_comments, activities, interests, music, movies, tv, books, games, about, quotes, can_post, can_see_all_posts, can_see_audio, can_write_private_message, timezone, screen_name&q={Query}&count={str(self.Limit)}")
                    JSON_Object = Common.JSON_Handler(VK_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Social Media - Person", self.Task_ID, self.Plugin_Name.lower())
                    New_JSON_Response = Recursive_Dict_Check(["response", "items"], JSON_Response)

                    if New_JSON_Response:

                        for VK_Item_Line in New_JSON_Response:

                            try:

                                if all(Item in VK_Item_Line for Item in ["first_name", "last_name", "screen_name"]):
                                    VK_URL = f"https://{self.Domain}/{VK_Item_Line['screen_name']}"
                                    Full_Name = f"{VK_Item_Line['first_name']} {VK_Item_Line['last_name']}"
                                    Title = f"VK User | {Full_Name}"

                                    if VK_URL not in Cached_Data and VK_URL not in Data_to_Cache:
                                        VK_Item_Responses = Common.Request_Handler(url=VK_URL, Filter=True, Host=f"https://{self.Domain}")
                                        VK_Item_Response = VK_Item_Responses["Filtered"]
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, VK_Item_Response, VK_URL, self.The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], VK_URL, Title, self.Plugin_Name.lower())
                                            Data_to_Cache.append(VK_URL)

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            except Exception as e:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

                elif self.Type == "Group":
                    VK_Response = Common.Request_Handler(url=f"https://api.{self.Domain}/method/groups.search?v=5.52&access_token={VK_Access_Token}&q={Query}&count={str(self.Limit)}")
                    JSON_Object = Common.JSON_Handler(VK_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Social Media - Group", self.Task_ID, self.Plugin_Name.lower())
                    New_JSON_Response = Recursive_Dict_Check(["response", "items"], JSON_Response)

                    if New_JSON_Response:

                        for VK_Item_Line in New_JSON_Response:

                            try:

                                if all(Item in VK_Item_Line for Item in ["name", "screen_name"]):
                                    VK_URL = f"https://{self.Domain}/{VK_Item_Line['screen_name']}"
                                    Title = f"VK Group | {VK_Item_Line['name']}"

                                    if VK_URL not in Cached_Data and VK_URL not in Data_to_Cache:
                                        VK_Item_Responses = Common.Request_Handler(url=VK_URL, Filter=True, Host=f"https://{self.Domain}")
                                        VK_Item_Response = VK_Item_Responses["Filtered"]
                                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, VK_Item_Response, VK_URL, self.The_File_Extensions["Query"])

                                        if Output_file:
                                            Output_Connections.Output([Main_File, Output_file], VK_URL, Title, self.Plugin_Name.lower())
                                            Data_to_Cache.append(VK_URL)

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                            except Exception as e:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type supplied.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")