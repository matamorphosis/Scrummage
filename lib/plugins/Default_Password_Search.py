#!/usr/bin/env python3
import logging, os, re, plugins.common.General as General

Plugin_Name = "Default-Password"
Concat_Plugin_Name = "defaultpassword"
The_File_Extension = ".html"
Domain = "default-password.info"
headers = General.URL_Headers(User_Agent=True, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True)

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
            URL_Body = f'https://{Domain}'
            Main_URL = URL_Body + '/' + Query.lower().replace(' ', '-')
            Responses = General.Request_Handler(Main_URL, Filter=True, Host=f"https://www.{Domain}")
            Response = Responses["Regular"]
            Filtered_Response = Responses["Filtered"]
            Main_File = General.Main_File_Create(Directory, Plugin_Name, Filtered_Response, Query, The_File_Extension)
            Regex = re.findall(r'\<tr\>\s+\<td\sclass\=\"name\"\>\s+\<a\shref\=\"([\/\d\w\-\+\?\.]+)\"\>([\/\d\w\-\+\?\.\(\)\s\,\;\:\~\`\!\@\#\$\%\^\&\*\[\]\{\}]+)\<\/a\>\s+\<\/td\>', Response)

            if Regex:
                Current_Step = 0
                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Credentials", Task_ID, Concat_Plugin_Name)

                for URL, Title in Regex:
                    Item_URL = URL_Body + URL
                    Current_Response = General.Request_Handler(Item_URL)
                    Current_Item_Regex = re.search(r'\<button\sclass\=\"btn\sbtn\-primary\spassword\"\s+data\-data\=\"([\-\d\w\?\/]+)\"\s+data\-toggle\=\"modal\"\s+data\-target\=\"\#modal\"\s+\>show\sme\!\<\/button\>', Current_Response)

                    if Current_Item_Regex:

                        try:
                            Detailed_Item_URL = URL_Body + Current_Item_Regex.group(1)
                            Detailed_Response = General.Request_Handler(Item_URL)
                            JSON_Response = General.Is_JSON(Detailed_Response)

                            if JSON_Response:
                                Output_Response = "<head><title>" + JSON_Response["title"] + "</title></head>\n"
                                Output_Response = Output_Response + JSON_Response["data"]

                            else:
                                Output_Response = General.Response_Filter(Detailed_Response, f"https://www.{Domain}")

                            if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Output_Response, Title, The_File_Extension)

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Item_URL, General.Get_Title(Item_URL), Concat_Plugin_Name)
                                    Data_to_Cache.append(Item_URL)

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                        except:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to generate output, may have a blank detailed response.")

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression for current result.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to match regular expression for provided query.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")