#!/usr/bin/env python3
import logging, os, json, plugins.common.General as General, plugins.common.Connectors as Connectors

Plugin_Name = "Vkontakte"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "vk.com"

def Load_Configuration():
    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Loading configuration data.")

    try:

        with open(Connectors.Set_Configuration_File()) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            VK_Details = Configuration_Data[Plugin_Name.lower()]
            VK_Access_Token = VK_Details['access_token']

            if VK_Access_Token:
                return VK_Access_Token

            else:
                return None

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to load API details.")

def Recursive_Dict_Check(Items, Dict_to_Check):

    try:

        for Item in Items:

            if Item in Dict_to_Check:
                Dict_to_Check = Dict_to_Check[Item]

            else:
                return False

        return Dict_to_Check

    except:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

def Search(Query_List, Task_ID, Type, **kwargs):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Plugin_Name.lower())
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Plugin_Name.lower())
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        VK_Access_Token = Load_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            if Type == "User":
                VK_Response = General.Request_Handler(f"https://api.{Domain}/method/users.search?v=5.52&access_token={VK_Access_Token}&fields=verified, blacklisted, sex, bdate, city, country, home_town, photo_50, photo_100, photo_200_orig, photo_200, photo_400_orig, photo_max, photo_max_orig, online, lists, domain, has_mobile, contacts, site, education, universities, schools, status, last_seen, followers_count, common_count, counters, occupation, nickname, relatives, relation, personal, connections, exports, wall_comments, activities, interests, music, movies, tv, books, games, about, quotes, can_post, can_see_all_posts, can_see_audio, can_write_private_message, timezone, screen_name&q={Query}&count={str(Limit)}")
                JSON_Response = json.loads(VK_Response)
                JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Social Media - Person", Task_ID, Plugin_Name.lower())
                New_JSON_Response = Recursive_Dict_Check(["response", "items"], JSON_Response)

                if New_JSON_Response:

                    for VK_Item_Line in New_JSON_Response:

                        try:

                            if all(Item in VK_Item_Line for Item in ["first_name", "last_name", "screen_name"]):
                                VK_URL = f"https://{Domain}/" + VK_Item_Line['screen_name']
                                Full_Name = VK_Item_Line["first_name"] + " " + VK_Item_Line["last_name"]
                                Title = f"VK User | {Full_Name}"

                                if VK_URL not in Cached_Data and VK_URL not in Data_to_Cache:
                                    VK_Item_Responses = General.Request_Handler(VK_URL, Filter=True, Host=f"https://{Domain}")
                                    VK_Item_Response = VK_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, VK_Item_Response, VK_URL, The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], VK_URL, Title, Plugin_Name.lower())
                                        Data_to_Cache.append(VK_URL)

                                    else:
                                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except Exception as e:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

            if Type == "Group":
                VK_Response = General.Request_Handler(f"https://api.{Domain}/method/groups.search?v=5.52&access_token={VK_Access_Token}&q={Query}&count={str(Limit)}")
                JSON_Response = json.loads(VK_Response)
                JSON_Output_Response = json.dumps(JSON_Response, indent=4, sort_keys=True)
                Main_File = General.Main_File_Create(Directory, Plugin_Name, JSON_Output_Response, Query, The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Social Media - Group", Task_ID, Plugin_Name.lower())
                New_JSON_Response = Recursive_Dict_Check(["response", "items"], JSON_Response)

                if New_JSON_Response:

                    for VK_Item_Line in New_JSON_Response:

                        try:

                            if all(Item in VK_Item_Line for Item in ["name", "screen_name"]):
                                VK_URL = f"https://{Domain}/" + VK_Item_Line['screen_name']
                                Full_Name = VK_Item_Line["name"]
                                Title = f"VK Group | {Full_Name}"

                                if VK_URL not in Cached_Data and VK_URL not in Data_to_Cache:
                                    VK_Item_Responses = General.Request_Handler(VK_URL, Filter=True, Host=f"https://{Domain}")
                                    VK_Item_Response = VK_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, VK_Item_Response, VK_URL, The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], VK_URL, Title, Plugin_Name.lower())
                                        Data_to_Cache.append(VK_URL)

                                    else:
                                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except Exception as e:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - No results found.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")