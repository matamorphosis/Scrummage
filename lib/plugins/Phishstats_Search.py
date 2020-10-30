#!/usr/bin/env python3
import logging, os, json, re, plugins.common.General as General

Plugin_Name = "Phishstats"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "phishstats.info"

def Search(Query_List, Task_ID, **kwargs):

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
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            try:
                Pull_URL = f"https://{Domain}:2096/api/phishing?_where=(url,like,~{Query}~)&_sort=-id&_size={Limit}"
                Results = json.loads(General.Request_Handler(Pull_URL))
                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Phishing", Task_ID, Plugin_Name.lower())
                Main_File = General.Main_File_Create(Directory, Plugin_Name, json.dumps(Results, indent=4, sort_keys=True), Query, The_File_Extensions["Main"])

                for Result in Results:
                    Current_Link = Result["url"]
                    Current_Domain = Current_Link.strip("https://")
                    Current_Domain = Current_Domain.strip("http://")
                    Current_Domain = Current_Domain.strip("www.")
                    Current_Title = Result["title"]

                    try:
                        Current_Result = General.Request_Handler(Current_Link, Filter=True, Risky_Plugin=True, Host=Current_Link)
                        Current_Result_Filtered = Current_Result["Filtered"]
                        Response_Regex = re.search(r"\<title\>([^\<\>]+)\<\/title\>", Current_Result)
                        Output_file_Query = Query.replace(" ", "-")

                        if Current_Link not in Cached_Data and Current_Link not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Output_file_Query, Plugin_Name, Current_Result_Filtered, Current_Domain, The_File_Extensions["Query"])

                            if Output_file:

                                if Response_Regex:
                                    Current_Title = Response_Regex.group(1)
                                    Current_Title = Current_Title.strip()
                                    Output_Connections.Output([Main_File, Output_file], Current_Link, Current_Title, Plugin_Name.lower())

                                else:

                                    if not "Phishstats" in Current_Title:
                                        Output_Connections.Output([Main_File, Output_file], Current_Link, Current_Title, Plugin_Name.lower())

                                    else:
                                        Output_Connections.Output([Main_File, Output_file], Current_Link, General.Get_Title(Current_Link), Plugin_Name.lower())

                                Data_to_Cache.append(Current_Link)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    except:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request for result, link may no longer be available.")

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")