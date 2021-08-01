#!/usr/bin/env python3
import os, feedparser, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.The_File_Extension = ".html"
        self.Plugin_Name = "RSS"
        self.Logging_Plugin_Name = self.Plugin_Name + " Feed Search"
        self.Result_Type = "News Report"
        self.Limit = General.Get_Limit(Limit)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)

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

            try:
                File_Dir = os.path.dirname(os.path.realpath('__file__'))
                Configuration_File = os.path.join(File_Dir, 'plugins/common/config/RSS_Feeds.txt')
                Current_File = open(Configuration_File, "r") # Open the provided file and retrieve each client to test.
                URLs = Current_File.read().splitlines()
                Current_File.close()

            except:
                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Please provide a valid RSS_Feeds file, failed to open the file which contains the data to search for.")

            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                for URL in URLs: # URLs to be controlled by the web app.
                    RSS = feedparser.parse(URL)
                    Current_Step = 0

                    for Feed in RSS.entries:

                        if Query in Feed.description:
                            Dump_Types = General.Data_Type_Discovery(Feed.description)
                            File_Link = Feed.link.replace("https://", "")
                            File_Link = File_Link.replace("http://", "")
                            File_Link = File_Link.replace("www.", "")
                            File_Link = File_Link.replace("/", "-")
                            Domain = URL.replace("https://", "")
                            Domain = Domain.replace("http://", "")
                            Domain = Domain.replace("www.", "")

                            if Feed.link not in Cached_Data and Feed.link not in Data_to_Cache and Current_Step < int(self.Limit):
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Feed.description, File_Link, self.The_File_Extension)
                                Title = "RSS Feed | " + General.Get_Title(Feed.link)

                                if Output_file:
                                    Output_Connections = General.Connections(Query, self.Plugin_Name, Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                                    Output_Connections.Output([Output_file], Feed.link, Title, self.Plugin_Name.lower(), Dump_Types=Dump_Types)
                                    Data_to_Cache.append(Feed.link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                        else:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Query not found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")