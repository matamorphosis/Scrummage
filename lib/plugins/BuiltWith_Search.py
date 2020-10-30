#!/usr/bin/env python3
import plugins.common.General as General, os, logging, json
from builtwith import builtwith

The_File_Extensions = {"Main": ".json", "Query": ".html"}
Plugin_Name = "BuiltWith"
Domain = "builtwith.com"

def Search(Query_List, Task_ID):

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
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)

        for Query in Query_List:
            URL_Regex = General.Regex_Checker(Query, "URL")

            if URL_Regex:
                BW_Info = builtwith(Query)

                if BW_Info:
                    BW_JSON_Output = json.dumps(BW_Info, indent=4, sort_keys=True)
                    URL_Body = URL_Regex.group(3)

                    if URL_Regex.group(5) and URL_Regex.group(6):
                        URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

                    elif URL_Regex.group(5):
                        URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

                    else:
                        URL_Extension = URL_Regex.group(4)

                    Query_Domain = URL_Body + URL_Extension
                    Title = f"Built With | {Query_Domain}"
                    Main_File = General.Main_File_Create(Directory, Plugin_Name, BW_JSON_Output, Query_Domain, The_File_Extensions["Main"])
                    BW_Search_URL = f"https://{Domain}/{Query_Domain}"
                    Responses = General.Request_Handler(BW_Search_URL, Filter=True, Host=f"https://{Domain}")
                    Response = Responses["Filtered"]
                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Web Application Architecture", Task_ID, Plugin_Name.lower())

                    if BW_Search_URL not in Cached_Data and BW_Search_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Response, Query, The_File_Extensions['Query'])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], BW_Search_URL, Title, Plugin_Name.lower())
                            Data_to_Cache.append(BW_Search_URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to get result for provided query.")

            else:
                logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid query provided.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")