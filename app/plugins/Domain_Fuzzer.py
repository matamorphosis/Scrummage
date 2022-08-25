#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, logging, socket, plugins.common.Rotor as Rotor, plugins.common.General as General, plugins.common.Common as Common, multiprocessing, multiprocessing.pool as mpool

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Query_List = General.Convert_to_List(Query_List)
        self.Task_ID = Task_ID
        self.Data_to_Cache: list = list()
        self.Cached_Data: list = list()
        self.Valid_Results: list = ["Domain,IP Address"]
        self.Valid_Hosts: list = list()
        self.Generic_Extensions: tuple = tuple(sorted([".com", ".edu", ".gov", ".net", ".info"]))
        self.Expired_Global_Domain_Suffixes: tuple = tuple(sorted([".cs", ".dd", ".gb", ".su", ".yu", ".zr"]))
        self.Global_Domain_Suffixes: tuple = (
            '.ac', '.ad', '.ae', '.af', '.ag', '.ai', '.al', '.am', '.an', '.ao', '.aq', '.ar', '.as', '.at', '.au', '.aw', '.ax', '.az', '.ba', '.bb', '.bd', '.be', '.bf', '.bg', '.bh', '.bi', '.bj', '.bm','.bn', '.bo', '.br', '.bs', '.bt',
            '.bv', '.bw', '.by', '.bz', '.ca', '.cat', '.cc', '.cd', '.cf', '.cg', '.ch', '.ci', '.ck', '.cl', '.cm', '.cn', '.cr', '.cu', '.cv', '.cw', '.cx', '.cy', '.cz', '.de', '.dj', '.dk', '.dm', '.do', '.dz', '.ec', '.ee', '.eg', '.er',
            '.es', '.et', '.eu', '.eus', '.fi', '.fj', '.fk', '.fm', '.fo', '.fr', '.ga', '.gal', '.gb', '.gd', '.ge', '.gf', '.gg', '.gh', '.gi', '.gl', '.gm', '.gn', '.gp', '.gq', '.gr', '.gs', '.gt', '.gu', '.gw', '.gy', '.hk', '.hm', '.hn',
            '.hr', '.ht', '.hu', '.id', '.ie', '.il', '.im', '.in', '.io', '.iq', '.ir', '.is', '.it', '.je', '.jm', '.jo', '.jp', '.ke', '.kg', '.kh', '.ki', '.km', '.kn', '.kp', '.kr', '.kw', '.ky', '.kz', '.la', '.lb', '.lc', '.li', '.lk',
            '.lr', '.ls', '.lt', '.lu', '.lv', '.ly', '.ma', '.mc', '.md', '.me', '.mg', '.mh', '.mk', '.ml', '.mm', '.mn', '.mo', '.mp', '.mq', '.mr', '.ms', '.mt', '.mu', '.mv', '.mw', '.mx', '.my', '.mz', '.na', '.nc', '.ne', '.nf', '.ng',
            '.ni', '.nl', '.no', '.np', '.nr', '.nu', '.nz', '.om', '.pa', '.pe', '.pf', '.pg', '.ph', '.pk', '.pl', '.pm', '.pn', '.pr', '.ps', '.pt', '.pw', '.py', '.qa', '.re', '.ro', '.rs', '.ru', '.rw', '.sa', '.sb', '.sc', '.sd', '.se',
            '.sg', '.sh', '.si', '.sj', '.sk', '.sl', '.sm', '.sn', '.so', '.sr', '.ss', '.st', '.sv', '.sy', '.sz', '.tc', '.td', '.tf', '.tg', '.th', '.tj', '.tk', '.tl', '.tm', '.tn', '.to', '.tp', '.tr', '.tt', '.tv', '.tw', '.tz', '.ua',
            '.ug', '.uk', '.us', '.uy', '.uz', '.va', '.vc', '.ve', '.vg', '.vi', '.vn', '.vu', '.wf', '.ws', '.ye', '.yt', '.za', '.zm', '.zw', '.co.ao', '.co.bw', '.co.ck', '.co.cr', '.co.gy', '.co.hu', '.co.id', '.co.il', '.co.im', '.co.in',
            '.co.je', '.co.jp', '.co.ke', '.co.kr', '.co.lc', '.co.ls', '.co.ma', '.co.mz', '.co.nz', '.co.pe', '.co.rs', '.co.th', '.co.tz', '.co.ug', '.co.uk', '.co.uz', '.co.ve', '.co.vi', '.co.za', '.co.zm', '.co.zw', '.com', '.com.af',
            '.com.ag', '.com.ai', '.com.aq', '.com.ar', '.com.au', '.com.bd', '.com.bh', '.com.bi', '.com.bn', '.com.bo', '.com.br', '.com.by', '.com.bz', '.com.cn', '.com.co', '.com.cu', '.com.cy', '.com.do', '.com.ec', '.com.eg', '.com.et',
            '.com.fj', '.com.ge', '.com.gh', '.com.gi', '.com.gp', '.com.gr', '.com.gt', '.com.gy', '.com.hk', '.com.ht', '.com.iq', '.com.jm', '.com.jo', '.com.kh', '.com.kw', '.com.kz', '.com.lb', '.com.ly', '.com.mm', '.com.mt', '.com.mx',
            '.com.my', '.com.na', '.com.nf', '.com.ng', '.com.ni', '.com.np', '.com.nr', '.com.om', '.com.pa', '.com.pe', '.com.pg', '.com.ph', '.com.pk', '.com.pl', '.com.pr', '.com.ps', '.com.py', '.com.qa', '.com.ru', '.com.sa', '.com.sb',
            '.com.sg', '.com.sl', '.com.sv', '.com.tj', '.com.ua', '.com.uy', '.com.vc', '.com.ve'
        )
        self.Plugin_Name: str = "Domain Fuzzer"
        self.Concat_Plugin_Name: str = "domainfuzzer"
        self.The_File_Extensions: dict = {"Main": ".csv", "Main_Alternative": ".json", "Query": ".html"}
        self.Logging_Plugin_Name: str = self.Plugin_Name + " Search"

    def Query_URL(self, URL, Extension):

        try:
            Query = URL + Extension
            Response = socket.gethostbyname(Query)
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Successfully resolved hostname {Query} to an IP address {Response}.")

            if Response:
                Cache = Query + ":" + Response

                if Cache not in self.Cached_Data and Cache not in self.Data_to_Cache:
                    HTTP_Web_Host: str = 'http://' + Query
                    Web_Host = HTTP_Web_Host
                    Response_Verdict = Common.Request_Handler(url=Web_Host, Risky_Plugin=True, verify=False)

                    if not Response_Verdict:
                        HTTPS_Web_Host = Web_Host.replace("http://", "https://")
                        Response_Verdict = Common.Request_Handler(url=Web_Host, Risky_Plugin=True, verify=False)
                        
                        if Response_Verdict:
                            Web_Host = HTTPS_Web_Host

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Unable to connect to a valid host neither via HTTP nor HTTPS. Result will still be created.")

                    self.Valid_Results.append(f"{Query},{Response}")
                    self.Data_to_Cache.append(Cache)
                    self.Valid_Hosts.append([Web_Host, Response])

        except:
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to resolve hostname {Query} to an IP address.")

    def Character_Switch(self, Alphabets, Comprehensive=False):

        try:
            Local_Plugin_Name = self.Plugin_Name + " Character Switch"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            self.Cached_Data = Cached_Data_Object.Get_Cache()
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Character Switching Selected.")

            for Query in self.Query_List:
                URL_Components = Common.Regex_Handler(Query, Type="URL", Get_URL_Components=True)

                if URL_Components:
                    self.URL_Prefix = URL_Components["Prefix"]
                    self.URL_Body = URL_Components["Body"]
                    self.URL_Extension = URL_Components["Extension"]

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query, please provide a valid URL.")

                logging.info(f'{Common.Date()} - Provided domain body - {self.URL_Body}')
                URL_List = list(self.URL_Body.lower())
                Local_Plugin_Name = f"{Local_Plugin_Name} {Alphabets}"
                Non_Comprehensive_Latin_Limit = 15
                Other_Limit = 10

                if Alphabets == "Latin":

                    if not Comprehensive:

                        if len(self.URL_Body) > Non_Comprehensive_Latin_Limit:
                            logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - The length of the body of the provided query: {Query} is greater than {str(Non_Comprehensive_Latin_Limit)} characters in length. Condensed punycode domain fuzzing only allows a maximum of {str(Non_Comprehensive_Latin_Limit)} characters.")
                            return None

                        else:
                            Altered_URLs = Rotor.Iterator(Query=URL_List, Latin=True, Latin_Alternatives=True).Search()

                    else:

                        if len(self.URL_Body) > Other_Limit:
                            logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - The length of the body of the provided query: {Query} is greater than {str(Other_Limit)} characters in length. Comprehensive punycode domain fuzzing searching only allows a maximum of {str(Other_Limit)} characters.")
                            return None

                        else:
                            Altered_URLs = Rotor.Iterator(Query=URL_List, Latin=True, Latin_Alternatives=True, Comprehensive=True).Search()

                elif Alphabets == "Asian":

                    if len(self.URL_Body) > Other_Limit:
                        logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - The length of the body of the provided query: {Query} is greater than {str(Other_Limit)} characters in length. Punycode domain fuzzing for Asian alphabets only allows a maximum of {str(Other_Limit)} characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Iterator(Query=URL_List, Asian=True).Search()

                elif Alphabets == "Middle Eastern":

                    if len(self.URL_Body) > Other_Limit:
                        logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - The length of the body of the provided query: {Query} is greater than {str(Other_Limit)} characters in length. Punycode domain fuzzing for Middle Eastern alphabets only allows a maximum of {str(Other_Limit)} characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Iterator(Query=URL_List, Middle_Eastern=True).Search()

                elif Alphabets == "Native American":

                    if len(self.URL_Body) > Other_Limit:
                        logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - The length of the body of the provided query: {Query} is greater than {str(Other_Limit)} characters in length. Punycode domain fuzzing for Asian alphabets only allows a maximum of {str(Other_Limit)} characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Iterator(Query=URL_List, Native_American=True).Search()

                elif Alphabets == "North African":

                    if len(self.URL_Body) > Other_Limit:
                        logging.error(f"{Common.Date()} - {self.Logging_Plugin_Name} - The length of the body of the provided query: {Query} is greater than {str(Other_Limit)} characters in length. Punycode domain fuzzing for Middle Eastern alphabets only allows a maximum of {str(Other_Limit)} characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Iterator(Query=URL_List, North_African=True).Search()


                logging.info(f'{Common.Date()} - Generated domain combinations - {", ".join(Altered_URLs)}')
                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count())*int(multiprocessing.cpu_count()))
                Pool_Threads: list = list()

                for Altered_URL in Altered_URLs:

                    if not Altered_URL == self.URL_Body:
                        Thread = Pool.apply_async(self.Query_URL, args=(Altered_URL, self.URL_Extension,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                logging.info(f'{Common.Date()} {Directory}')
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])
                Main_File_JSON_Data = General.CSV_to_JSON(Query, self.Valid_Results)
                Main_File_HTML_Data = General.CSV_to_HTML(self.Valid_Results, f"Domain Spoof Results for Query {Query}")
                Main_File_JSON = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_JSON_Data, self.URL_Body, self.The_File_Extensions["Main_Alternative"])
                Main_File_HTML = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_HTML_Data, self.URL_Body, self.The_File_Extensions["Query"])

                if Main_File and Main_File_HTML and Main_File_JSON:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')
                        Current_Responses = Common.Request_Handler(url=Host[0], Filter=True, Host=Host[0], Risky_Plugin=True, verify=False)
                        Current_Response = Current_Responses["Filtered"]
                        Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])
                        Defanged_Title_Objects = Common.Fang().Defang_List([URL_Domain, Current_Domain, Host[1]])
                        Title = f"Domain Spoof for {Defanged_Title_Objects[0]} - {Defanged_Title_Objects[1]} : {Defanged_Title_Objects[2]}"

                        if Output_File:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON, Output_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

                        else:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

            Cached_Data_Object.Write_Cache(self.Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")


    def Regular_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + " Regular Extensions"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            self.Cached_Data = Cached_Data_Object.Get_Cache()
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Regular Extensions Selected.")

            for Query in self.Query_List:
                URL_Components = Common.Regex_Handler(Query, Type="URL", Get_URL_Components=True)

                if URL_Components:
                    self.URL_Prefix = URL_Components["Prefix"]
                    self.URL_Body = URL_Components["Body"]
                    self.URL_Extension = URL_Components["Extension"]

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query, please provide a valid URL.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads: list = list()

                for Extension in self.Generic_Extensions:

                    if not self.URL_Extension == Extension:
                        Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, Extension,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])
                Main_File_JSON_Data = General.CSV_to_JSON(Query, self.Valid_Results)
                Main_File_HTML_Data = General.CSV_to_HTML(self.Valid_Results, f"Domain Spoof Results for Query {Query}")
                Main_File_JSON = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_JSON_Data, self.URL_Body, self.The_File_Extensions["Main_Alternative"])
                Main_File_HTML = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_HTML_Data, self.URL_Body, self.The_File_Extensions["Query"])

                if Main_File and Main_File_HTML and Main_File_JSON:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')
                        Current_Responses = Common.Request_Handler(url=Host[0], Filter=True, Host=Host[0], Risky_Plugin=True, verify=False)
                        Current_Response = Current_Responses["Filtered"]
                        Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])
                        Defanged_Title_Objects = Common.Fang().Defang_List([URL_Domain, Current_Domain, Host[1]])
                        Title = f"Domain Spoof for {Defanged_Title_Objects[0]} - {Defanged_Title_Objects[1]} : {Defanged_Title_Objects[2]}"

                        if Output_File:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON, Output_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

                        else:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

            Cached_Data_Object.Write_Cache(self.Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")


    def Global_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + " Global Suffixes"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            self.Cached_Data = Cached_Data_Object.Get_Cache()
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Global Suffixes Selected.")

            for Query in self.Query_List:
                URL_Components = Common.Regex_Handler(Query, Type="URL", Get_URL_Components=True)

                if URL_Components:
                    self.URL_Prefix = URL_Components["Prefix"]
                    self.URL_Body = URL_Components["Body"]
                    self.URL_Extension = URL_Components["Extension"]

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query, please provide a valid URL.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads: list = list()

                for suffix in self.Global_Domain_Suffixes:

                    if not self.URL_Extension == suffix:
                        Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, suffix,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])
                Main_File_JSON_Data = General.CSV_to_JSON(Query, self.Valid_Results)
                Main_File_HTML_Data = General.CSV_to_HTML(self.Valid_Results, f"Domain Spoof Results for Query {Query}")
                Main_File_JSON = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_JSON_Data, self.URL_Body, self.The_File_Extensions["Main_Alternative"])
                Main_File_HTML = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_HTML_Data, self.URL_Body, self.The_File_Extensions["Query"])

                if Main_File and Main_File_HTML and Main_File_JSON:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')
                        Current_Responses = Common.Request_Handler(url=Host[0], Filter=True, Host=Host[0], Risky_Plugin=True, verify=False)
                        Current_Response = Current_Responses["Filtered"]
                        Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])
                        Defanged_Title_Objects = Common.Fang().Defang_List([URL_Domain, Current_Domain, Host[1]])
                        Title = f"Domain Spoof for {Defanged_Title_Objects[0]} - {Defanged_Title_Objects[1]} : {Defanged_Title_Objects[2]}"

                        if Output_File:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON, Output_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

                        else:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

            Cached_Data_Object.Write_Cache(self.Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")


    def Expired_Global_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + " Expired Global Suffixes"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            self.Cached_Data = Cached_Data_Object.Get_Cache()
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Expired Global Suffixes Selected.")

            for Query in self.Query_List:
                URL_Components = Common.Regex_Handler(Query, Type="URL", Get_URL_Components=True)

                if URL_Components:
                    self.URL_Prefix = URL_Components["Prefix"]
                    self.URL_Body = URL_Components["Body"]
                    self.URL_Extension = URL_Components["Extension"]

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query, please provide a valid URL.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads: list = list()

                for suffix in self.Expired_Global_Domain_Suffixes:

                    if not self.URL_Extension == suffix:
                        Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, suffix,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])
                Main_File_JSON_Data = General.CSV_to_JSON(Query, self.Valid_Results)
                Main_File_HTML_Data = General.CSV_to_HTML(self.Valid_Results, f"Domain Spoof Results for Query {Query}")
                Main_File_JSON = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_JSON_Data, self.URL_Body, self.The_File_Extensions["Main_Alternative"])
                Main_File_HTML = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_HTML_Data, self.URL_Body, self.The_File_Extensions["Query"])

                if Main_File and Main_File_HTML and Main_File_JSON:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')
                        Current_Responses = Common.Request_Handler(url=Host[0], Filter=True, Host=Host[0], Risky_Plugin=True, verify=False)
                        Current_Response = Current_Responses["Filtered"]
                        Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])
                        Defanged_Title_Objects = Common.Fang().Defang_List([URL_Domain, Current_Domain, Host[1]])
                        Title = f"Domain Spoof for {Defanged_Title_Objects[0]} - {Defanged_Title_Objects[1]} : {Defanged_Title_Objects[2]}"

                        if Output_File:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON, Output_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

                        else:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

            Cached_Data_Object.Write_Cache(self.Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")


    def All_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + " All Extensions"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            self.Cached_Data = Cached_Data_Object.Get_Cache()
            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - All Extensions Selected.")

            for Query in self.Query_List:
                URL_Components = Common.Regex_Handler(Query, Type="URL", Get_URL_Components=True)

                if URL_Components:
                    self.URL_Prefix = URL_Components["Prefix"]
                    self.URL_Body = URL_Components["Body"]
                    self.URL_Extension = URL_Components["Extension"]

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query, please provide a valid URL.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads: list = list()

                for Extension in self.Generic_Extensions:
                    All_Domain_Suffixes: list = list()
                    All_Domain_Suffixes.extend(self.Global_Domain_Suffixes)
                    All_Domain_Suffixes.extend(self.Expired_Global_Domain_Suffixes)

                    for suffix in All_Domain_Suffixes:
                        suffix = suffix.replace(".com", "")
                        suffix = suffix.replace(".co", "")

                        if not self.URL_Extension == suffix:
                            Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, Extension + suffix,))
                            Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])
                Main_File_JSON_Data = General.CSV_to_JSON(Query, self.Valid_Results)
                Main_File_HTML_Data = General.CSV_to_HTML(self.Valid_Results, f"Domain Spoof Results for Query {Query}")
                Main_File_JSON = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_JSON_Data, self.URL_Body, self.The_File_Extensions["Main_Alternative"])
                Main_File_HTML = General.Main_File_Create(Directory, Local_Plugin_Name, Main_File_HTML_Data, self.URL_Body, self.The_File_Extensions["Query"])

                if Main_File and Main_File_HTML and Main_File_JSON:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')
                        Current_Responses = Common.Request_Handler(url=Host[0], Filter=True, Host=Host[0], Risky_Plugin=True, verify=False)
                        Current_Response = Current_Responses["Filtered"]
                        Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])
                        Defanged_Title_Objects = Common.Fang().Defang_List([URL_Domain, Current_Domain, Host[1]])
                        Title = f"Domain Spoof for {Defanged_Title_Objects[0]} - {Defanged_Title_Objects[1]} : {Defanged_Title_Objects[2]}"

                        if Output_File:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON, Output_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

                        else:
                            Output_File_List = [Main_File, Main_File_HTML, Main_File_JSON]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], Title, Directory_Plugin_Name=self.Concat_Plugin_Name)

            Cached_Data_Object.Write_Cache(self.Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")