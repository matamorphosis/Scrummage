#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, logging, socket, requests, plugins.common.Rotor as Rotor, plugins.common.General as General, multiprocessing, multiprocessing.pool as mpool
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
headers = General.URL_Headers(User_Agent=True)

class Fuzzer:

    def __init__(self, Query_List, Task_ID):
        self.Query_List = Query_List
        self.Task_ID = Task_ID
        self.Data_to_Cache = []
        self.Cached_Data = []
        self.Valid_Results = ["Domain,IP Address"]
        self.Valid_Hosts = []
        self.Generic_Extensions = [".com", ".edu", ".gov", ".net", ".info"]
        self.Global_Domain_Suffixes = [".ac", ".ac", ".ad", ".ae", ".af", ".ag", ".ai", ".al", ".am", ".as", ".at", ".az", ".ba",
                                  ".be", ".bf", ".bg", ".bi", ".bj", ".bo", ".bs", ".bt", ".by", ".ca", ".cc", ".cd", ".cf",
                                  ".cg", ".ch", ".ci", ".cl", ".cm", ".cn", ".co", ".cv", ".cz", ".de", ".dj", ".dk", ".dm",
                                  ".dz", ".ec", ".ee", ".es", ".eu", ".fi", ".fm", ".fr", ".ga", ".ge", ".gf", ".gg", ".gl",
                                  ".gm", ".gp", ".gr", ".gy", ".hk", ".hn", ".hr", ".ht", ".hu", ".id", ".ie", ".im", ".in",
                                  ".io", ".iq", ".is", ".it", ".je", ".jo", ".jp", ".kg", ".ki", ".kz", ".la", ".li", ".lk",
                                  ".lt", ".lu", ".lv", ".ma", ".md", ".me", ".mg", ".mk", ".ml", ".mn", ".ms", ".mu", ".mv",
                                  ".mw", ".mx", ".ne", ".ng", ".nl", ".no", ".nr", ".nu", ".pf", ".pk", ".pl", ".pn", ".ps",
                                  ".pt", ".qa", ".re", ".ro", ".rs", ".ru", ".rw", ".sc", ".se", ".sh", ".si", ".sk", ".sl",
                                  ".sm", ".sn", ".so", ".sr", ".st", ".sy", ".td", ".tg", ".tk", ".tl", ".tm", ".tn", ".to",
                                  ".tt", ".ua", ".us", ".uz", ".vg", ".vn", ".vu", ".ws", ".co", ".co.am", ".co.ao", ".co.bw",
                                  ".co.ck", ".co.cr", ".co.gy", ".co.hu", ".co.id", ".co.il", ".co.im", ".co.in", ".co.je",
                                  ".co.jp", ".co.ke", ".co.kr", ".co.lc", ".co.ls", ".co.ma", ".co.mz", ".co.nz", ".co.pe",
                                  ".co.rs", ".co.th", ".co.tz", ".co.ug", ".co.uk", ".co.uz", ".co.ve", ".co.vi", ".co.za",
                                  ".co.zm", ".co.zw", ".com", ".com.af", ".com.ag", ".com.ai", ".com.aq", ".com.ar", ".com.au",
                                  ".com.bd", ".com.bh", ".com.bi", ".com.bn", ".com.bo", ".com.br", ".com.by", ".com.bz",
                                  ".com.cn", ".com.co", ".com.cu", ".com.cy", ".com.do", ".com.ec", ".com.eg", ".com.et",
                                  ".com.fj", ".com.ge", ".com.gh", ".com.gi", ".com.gp", ".com.gr", ".com.gt", ".com.gy",
                                  ".com.hk", ".com.ht", ".com.iq", ".com.jm", ".com.jo", ".com.kh", ".com.kw", ".com.kz",
                                  ".com.lb", ".com.ly", ".com.mm", ".com.mt", ".com.mx", ".com.my", ".com.na", ".com.nf",
                                  ".com.ng", ".com.ni", ".com.np", ".com.nr", ".com.om", ".com.pa", ".com.pe", ".com.pg",
                                  ".com.ph", ".com.pk", ".com.pl", ".com.pr", ".com.ps", ".com.py", ".com.qa", ".com.ru",
                                  ".com.sa", ".com.sb", ".com.sg", ".com.sl", ".com.sv", ".com.tj", ".com.ua", ".com.uy",
                                  ".com.vc", ".com.ve"]
        self.Plugin_Name = "Domain-Fuzzer"
        self.Concat_Plugin_Name = "urlfuzzer"
        self.The_File_Extensions = {"Main": ".csv", "Query": ".html"}

    def Query_URL(self, URL, Extension):

        try:
            Query = URL + Extension
            Response = socket.gethostbyname(Query)
            logging.info(f"{General.Date()} {__name__.strip('plugins.')} - Successfully resolved hostname {Query} to IP address {Response}.")

            if Response:
                Cache = Query + ":" + Response

                if Cache not in self.Cached_Data and Cache not in self.Data_to_Cache:

                    try:
                        HTTP_Web_Host = 'http://' + Query
                        Web_Host = HTTP_Web_Host
                        requests.get(Web_Host, headers=headers, verify=False)

                    except requests.exceptions.ConnectionError as ConnErr:

                        try:
                            HTTPS_Web_Host = Web_Host.replace("http://", "https://")
                            requests.get(HTTPS_Web_Host, headers=headers, verify=False)
                            Web_Host = HTTPS_Web_Host

                        except requests.exceptions.ConnectionError as ConnErr:
                            logging.warning(f"{General.Date()} {__name__.strip('plugins.')} - Unable to connect to a valid host neither via HTTP nor HTTPS. Result will still be created.")

                    self.Valid_Results.append(f"{Query},{Response}")
                    self.Data_to_Cache.append(Cache)
                    self.Valid_Hosts.append([Web_Host, Response])

        except:
            logging.info(f"{General.Date()} {__name__.strip('plugins.')} - Failed to resolve hostname {Query} to IP address.")

    def Character_Switch(self, Alphabets, Comprehensive_Search):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-Character-Switch"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            self.Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)
            logging.info(f"{General.Date()} {__name__.strip('plugins.')} - Character Switching Selected.")
            self.Query_List = General.Convert_to_List(self.Query_List)

            for Query in self.Query_List:
                URL_Regex = General.Regex_Checker(Query, "URL")

                if URL_Regex:
                    self.URL_Prefix = URL_Regex.group(1)
                    self.URL_Body = URL_Regex.group(3)

                    if URL_Regex.group(5) and URL_Regex.group(6):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

                    elif URL_Regex.group(5):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

                    else:
                        self.URL_Extension = URL_Regex.group(4)

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Please provide valid URLs.")

                logging.info(f'{General.Date()} - Provided domain body - {self.URL_Body}')
                URL_List = list(self.URL_Body.lower())
                Local_Plugin_Name = f"{Local_Plugin_Name}-{Alphabets}"

                if Alphabets == "Latin":

                    if not Comprehensive_Search:

                        if len(self.URL_Body) > 15:
                            logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - The length of the body of the provided query: {Query} is greater than 15 characters in length. Condensed punycode domain fuzzing only allows a maximum of 15 characters.")
                            return None

                        else:
                            Altered_URLs = Rotor.Search(URL_List, English_Upper=False, Numbers=False, Special_Characters=False, Asian=False, Latin=True, Middle_Eastern=False, Native_American=False, North_African=False, Latin_Alternatives=True, Comprehensive=False)

                    else:

                        if len(self.URL_Body) > 10:
                            logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - The length of the body of the provided query: {Query} is greater than 10 characters in length. Comprehensive punycode domain fuzzing searching only allows a maximum of 10 characters.")
                            return None

                        else:
                            Altered_URLs = Rotor.Search(URL_List, English_Upper=False, Numbers=False, Special_Characters=False, Asian=False, Latin=True, Middle_Eastern=False, Native_American=False, North_African=False, Latin_Alternatives=True, Comprehensive=True)

                elif Alphabets == "Asian":

                    if len(self.URL_Body) > 10:
                        logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - The length of the body of the provided query: {Query} is greater than 15 characters in length. Punycode domain fuzzing for Asian alphabets only allows a maximum of 10 characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Search(URL_List, English_Upper=False, Numbers=False, Special_Characters=False, Asian=True, Latin=False, Middle_Eastern=False, Native_American=False, North_African=False, Latin_Alternatives=False, Comprehensive=False)

                elif Alphabets == "Middle Eastern":

                    if len(self.URL_Body) > 10:
                        logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - The length of the body of the provided query: {Query} is greater than 15 characters in length. Punycode domain fuzzing for Middle Eastern alphabets only allows a maximum of 10 characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Search(URL_List, English_Upper=False, Numbers=False, Special_Characters=False, Asian=False, Latin=False, Middle_Eastern=True, Native_American=False, North_African=False, Latin_Alternatives=False, Comprehensive=False)

                elif Alphabets == "Native American":

                    if len(self.URL_Body) > 10:
                        logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - The length of the body of the provided query: {Query} is greater than 15 characters in length. Punycode domain fuzzing for Asian alphabets only allows a maximum of 10 characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Search(URL_List, English_Upper=False, Numbers=False, Special_Characters=False, Asian=False, Latin=False, Middle_Eastern=False, Native_American=True, North_African=False, Latin_Alternatives=False, Comprehensive=False)

                elif Alphabets == "North African":

                    if len(self.URL_Body) > 10:
                        logging.error(f"{General.Date()} - {__name__.strip('plugins.')} - The length of the body of the provided query: {Query} is greater than 15 characters in length. Punycode domain fuzzing for Middle Eastern alphabets only allows a maximum of 10 characters.")
                        return None

                    else:
                        Altered_URLs = Rotor.Search(URL_List, English_Upper=False, Numbers=False, Special_Characters=False, Asian=False, Latin=False, Middle_Eastern=False, Native_American=False, North_African=True, Latin_Alternatives=False, Comprehensive=False)


                logging.info(f'{General.Date()} - Generated domain combinations - {", ".join(Altered_URLs)}')
                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count())*int(multiprocessing.cpu_count()))
                Pool_Threads = []

                for Altered_URL in Altered_URLs:

                    if not Altered_URL == self.URL_Body:
                        Thread = Pool.apply_async(self.Query_URL, args=(Altered_URL, self.URL_Extension,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                logging.info(f'{General.Date()} {Directory}')
                URL_Domain = self.URL_Body + self.URL_Extension
                logging.info(URL_Domain)
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])
                logging.info(Main_File)

                if Main_File:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')

                        try:
                            Current_Response = requests.get(Host[0], headers=headers, verify=False).text
                            Current_Response = General.Response_Filter(Current_Response, Host[0], Risky_Plugin=True)
                            Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])

                            if Output_File:
                                Output_File_List = [Main_File, Output_File]
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except requests.exceptions.ConnectionError as ConnErr:
                            Output_File_List = [Main_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

            if self.Cached_Data:
                General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "a")

            else:
                General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "w")

        except Exception as e:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")


    def Regular_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-Regular-Extensions"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            self.Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)
            logging.info(f"{General.Date()} {__name__.strip('plugins.')} - Regular Extensions Selected.")
            self.Query_List = General.Convert_to_List(self.Query_List)

            for Query in self.Query_List:
                URL_Regex = General.Regex_Checker(Query, "URL")

                if URL_Regex:
                    self.URL_Prefix = URL_Regex.group(1)
                    self.URL_Body = URL_Regex.group(3)

                    if URL_Regex.group(5) and URL_Regex.group(6):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

                    elif URL_Regex.group(5):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

                    else:
                        self.URL_Extension = URL_Regex.group(4)

                else:
                    logging.warning(f"{General.Date()} {__name__.strip('plugins.')} - Please provide valid URLs.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads = []

                for Extension in self.Generic_Extensions:

                    if not self.URL_Extension == Extension:
                        Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, Extension,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])

                if Main_File:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')

                        try:
                            Current_Response = requests.get(Host[0], headers=headers, verify=False).text
                            Current_Response = General.Response_Filter(Current_Response, Host[0], Risky_Plugin=True)
                            Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])

                            if Output_File:
                                Output_File_List = [Main_File, Output_File]
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except requests.exceptions.ConnectionError as ConnErr:
                            Output_File_List = [Main_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

            if self.Cached_Data:
                General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "a")

            else:
                General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "w")

        except Exception as e:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")


    def Global_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-Global-Suffixes"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            self.Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)
            logging.info(f"{General.Date()} {__name__.strip('plugins.')} - Global Suffixes Selected.")
            self.Query_List = General.Convert_to_List(self.Query_List)

            for Query in self.Query_List:
                URL_Regex = General.Regex_Checker(Query, "URL")

                if URL_Regex:
                    self.URL_Prefix = URL_Regex.group(1)
                    self.URL_Body = URL_Regex.group(3)

                    if URL_Regex.group(5) and URL_Regex.group(6):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

                    elif URL_Regex.group(5):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

                    else:
                        self.URL_Extension = URL_Regex.group(4)

                else:
                    logging.warning(f"{General.Date()} {__name__.strip('plugins.')} - Please provide valid URLs.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads = []

                for suffix in self.Global_Domain_Suffixes:

                    if not self.URL_Extension == suffix:
                        Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, suffix,))
                        Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])

                if Main_File:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')

                        try:
                            Current_Response = requests.get(Host[0], headers=headers, verify=False).text
                            Current_Response = General.Response_Filter(Current_Response, Host[0], Risky_Plugin=True)
                            Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])

                            if Output_File:
                                Output_File_List = [Main_File, Output_File]
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except requests.exceptions.ConnectionError as ConnErr:
                            Output_File_List = [Main_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

            if self.Data_to_Cache:

                if self.Cached_Data:
                    General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "a")

                else:
                    General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "w")

        except Exception as e:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")


    def All_Extensions(self):

        try:
            Local_Plugin_Name = self.Plugin_Name + "-All-Extensions"
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, Local_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            self.Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)
            logging.info(f"{General.Date()} {__name__.strip('plugins.')} - All Extensions Selected.")
            self.Query_List = General.Convert_to_List(self.Query_List)

            for Query in self.Query_List:
                URL_Regex = General.Regex_Checker(Query, "URL")

                if URL_Regex:
                    self.URL_Prefix = URL_Regex.group(1)
                    self.URL_Body = URL_Regex.group(3)

                    if URL_Regex.group(5) and URL_Regex.group(6):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

                    elif URL_Regex.group(5):
                        self.URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

                    else:
                        self.URL_Extension = URL_Regex.group(4)

                else:
                    logging.warning(f"{General.Date()} {__name__.strip('plugins.')} - Please provide valid URLs.")

                Pool = mpool.ThreadPool(int(multiprocessing.cpu_count()) * int(multiprocessing.cpu_count()))
                Pool_Threads = []

                for Extension in self.Generic_Extensions:

                    for suffix in self.Global_Domain_Suffixes:
                        suffix = suffix.replace(".com", "")
                        suffix = suffix.replace(".co", "")

                        if not self.URL_Extension == suffix:
                            Thread = Pool.apply_async(self.Query_URL, args=(self.URL_Body, Extension + suffix,))
                            Pool_Threads.append(Thread)

                [Pool_Thread.wait() for Pool_Thread in Pool_Threads]
                URL_Domain = self.URL_Body + self.URL_Extension
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(self.Valid_Results), self.URL_Body, self.The_File_Extensions["Main"])

                if Main_File:

                    for Host in self.Valid_Hosts:
                        Current_Domain = Host[0].strip('https://').strip('http://')

                        try:
                            Current_Response = requests.get(Host[0], headers=headers, verify=False).text
                            Current_Response = General.Response_Filter(Current_Response, Host[0], Risky_Plugin=True)
                            Output_File = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Current_Response, Current_Domain, self.The_File_Extensions["Query"])

                            if Output_File:
                                Output_File_List = [Main_File, Output_File]
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        except requests.exceptions.ConnectionError as ConnErr:
                            Output_File_List = [Main_File]
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Current_Domain, "Domain Spoof", self.Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output(Output_File_List, Host[0], f"Domain Spoof for {URL_Domain} - {Current_Domain} : {Host[1]}", Directory_Plugin_Name=self.Concat_Plugin_Name)

                if self.Data_to_Cache:

                    if self.Cached_Data:
                        General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "a")

                    else:
                        General.Write_Cache(Directory, self.Data_to_Cache, Local_Plugin_Name, "w")

        except Exception as e:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")