#!/usr/bin/env python3
import re, os, logging, plugins.common.General as General

Plugin_Name = "Library-Genesis"
Concat_Plugin_Name = "libgen"
The_File_Extension = ".html"
Domain = "gen.lib.rus.ec"

def Search(Query_List, Task_ID, **kwargs):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Concat_Plugin_Name)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Concat_Plugin_Name)
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:
            # Query can be Title or ISBN
            Main_URL = f"http://{Domain}/search.php?req={Query}&lg_topic=libgen&open=0&view=simple&res=100&phrase=1&column=def"
            Lib_Gen_Response = General.Request_Handler(Main_URL)
            Main_File = General.Main_File_Create(Directory, Plugin_Name, Lib_Gen_Response, Query, The_File_Extension)
            Lib_Gen_Regex = re.findall("book\/index\.php\?md5=[A-Fa-f0-9]{32}", Lib_Gen_Response)

            if Lib_Gen_Regex:
                Current_Step = 0

                for Regex in Lib_Gen_Regex:
                    Item_URL = f"http://{Domain}/{Regex}"
                    Title = General.Get_Title(Item_URL).replace("Genesis:", "Genesis |")
                    Lib_Item_Responses = General.Request_Handler(Item_URL, Filter=True, Host=f"http://{Domain}")
                    Lib_Item_Response = Lib_Item_Responses["Filtered"]

                    if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Lib_Item_Response, Regex, The_File_Extension)

                        if Output_file:
                            Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Publication", Task_ID, Concat_Plugin_Name)
                            Output_Connections.Output([Main_File, Output_file], Item_URL, Title, Concat_Plugin_Name)
                            Data_to_Cache.append(Item_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        Current_Step += 1

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")