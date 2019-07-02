#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re, sys, datetime, socket, plugins.common.Rotor as Rotor, plugins.common.General as General

Generic_Extensions = [".com", ".edu", ".gov", ".net", ".info"]
Global_Domain_Suffixes = [".ac", ".ac", ".ad", ".ae", ".af", ".ag", ".ai", ".al", ".am", ".as", ".at", ".az", ".ba", ".be", ".bf", ".bg", ".bi", ".bj", ".bo", ".bs", ".bt", ".by", ".ca", ".cc", ".cd", ".cf", ".cg", ".ch", ".ci", ".cl", ".cm", ".cn", ".co", ".cv", ".cz", ".de", ".dj", ".dk", ".dm", ".dz", ".ec", ".ee", ".es", ".eu", ".fi", ".fm", ".fr", ".ga", ".ge", ".gf", ".gg", ".gl", ".gm", ".gp", ".gr", ".gy", ".hk", ".hn", ".hr", ".ht", ".hu", ".id", ".ie", ".im", ".in", ".io", ".iq", ".is", ".it", ".je", ".jo", ".jp", ".kg", ".ki", ".kz", ".la", ".li", ".lk", ".lt", ".lu", ".lv", ".ma", ".md", ".me", ".mg", ".mk", ".ml", ".mn", ".ms", ".mu", ".mv", ".mw", ".mx", ".ne", ".ng", ".nl", ".no", ".nr", ".nu", ".pf", ".pk", ".pl", ".pn", ".ps", ".pt", ".qa", ".re", ".ro", ".rs", ".ru", ".rw", ".sc", ".se", ".sh", ".si", ".sk", ".sl", ".sm", ".sn", ".so", ".sr", ".st", ".sy", ".td", ".tg", ".tk", ".tl", ".tm", ".tn", ".to", ".tt", ".ua", ".us", ".uz", ".vg", ".vn", ".vu", ".ws", ".co", ".co.am", ".co.ao", ".co.bw", ".co.ck", ".co.cr", ".co.gy", ".co.hu", ".co.id", ".co.il", ".co.im", ".co.in", ".co.je", ".co.jp", ".co.ke", ".co.kr", ".co.lc", ".co.ls", ".co.ma", ".co.mz", ".co.nz", ".co.pe", ".co.rs", ".co.th", ".co.tz", ".co.ug", ".co.uk", ".co.uz", ".co.ve", ".co.vi", ".co.za", ".co.zm", ".co.zw", ".com", ".com.af", ".com.ag", ".com.ai", ".com.aq", ".com.ar", ".com.au", ".com.bd", ".com.bh", ".com.bi", ".com.bn", ".com.bo", ".com.br", ".com.by", ".com.bz", ".com.cn", ".com.co", ".com.cu", ".com.cy", ".com.do", ".com.ec", ".com.eg", ".com.et", ".com.fj", ".com.ge", ".com.gh", ".com.gi", ".com.gp", ".com.gr", ".com.gt", ".com.gy", ".com.hk", ".com.ht", ".com.iq", ".com.jm", ".com.jo", ".com.kh", ".com.kw", ".com.kz", ".com.lb", ".com.ly", ".com.mm", ".com.mt", ".com.mx", ".com.my", ".com.na", ".com.nf", ".com.ng", ".com.ni", ".com.np", ".com.nr", ".com.om", ".com.pa", ".com.pe", ".com.pg", ".com.ph", ".com.pk", ".com.pl", ".com.pr", ".com.ps", ".com.py", ".com.qa", ".com.ru", ".com.sa", ".com.sb", ".com.sg", ".com.sl", ".com.sv", ".com.tj", ".com.ua", ".com.uy", ".com.vc", ".com.ve"]
Plugin_Name = "Domain-Fuzzer"
Concat_Plugin_Name = "urlfuzzer"
The_File_Extension = ".csv"

def Character_Switch(Query_List, Task_ID):
	Local_Plugin_Name = Plugin_Name + "-Character-Switch"
	Data_to_Cache = []
	Cached_Data = []
	Valid_Results = ["Domain,IP Address"]
	Valid_Hosts = []
	Directory = General.Make_Directory(Concat_Plugin_Name)
	General.Logging(Directory, Local_Plugin_Name)
	Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

	if not Cached_Data:
		Cached_Data = []

	print(str(datetime.datetime.now()) + " Character Switching Selected.")
	Query_List = General.Convert_to_List(Query_List)

	for Query in Query_List:
		URL_Regex = re.search(r"(https?:\/\/(www\.)?)?([-a-zA-Z0-9@:%_\+~#=]{2,256})(\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?", Query)

		if URL_Regex:
			URL_Prefix = URL_Regex.group(1)
			URL_Body = URL_Regex.group(3)

			if URL_Regex.group(5) and URL_Regex.group(6):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

			elif URL_Regex.group(5):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

			else:
				URL_Extension = URL_Regex.group(4)

		else:
			sys.exit(str(datetime.datetime.now()) + " Please provide valid URLs.")

		print(str(datetime.datetime.now()) + URL_Body)
		URL_List = list(URL_Body)
		Altered_URLs = Rotor.Search(URL_List, True, False, False, False, True, True, True)
		print(str(datetime.datetime.now()) + ", ".join(Altered_URLs))

		for Altered_URL in Altered_URLs:

			if not Altered_URL == URL_Body:

				try:
					Query = Altered_URL + URL_Extension
					Web_Host = URL_Prefix.replace("s", "") + Query
					Response = socket.gethostbyname(Query)

					if Response:
						Cache = Query + ":" + Response

						if Cache not in Cached_Data and Cache not in Data_to_Cache:
							Valid_Results.append(Query + "," + Response)
							Data_to_Cache.append(Cache)
							Valid_Hosts.append(Web_Host)

				except Exception as e:
					print(str(datetime.datetime.now()) + e)

		print(str(datetime.datetime.now()) + Directory)
		URL_Domain = URL_Body + URL_Extension
		Output_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(Valid_Results), URL_Body, The_File_Extension)

		if Output_File:

			for Host in Valid_Hosts:
				General.Connections(Output_File, Query, Local_Plugin_Name, Host, URL_Domain, "Domain Spoof", Task_ID, General.Get_Title(Host))

	if Cached_Data:
		General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

	else:
		General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

def Regular_Extensions(Query_List, Task_ID):
	Local_Plugin_Name = Plugin_Name + "-Regular-Extensions"
	Data_to_Cache = []
	Cached_Data = []
	Valid_Results = ["Domain,IP Address"]
	Valid_Hosts = []
	Directory = General.Make_Directory(Concat_Plugin_Name)
	General.Logging(Directory, Local_Plugin_Name)
	Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

	if not Cached_Data:
		Cached_Data = []

	print(str(datetime.datetime.now()) + " Regular Extensions Selected.")
	Query_List = General.Convert_to_List(Query_List)

	for Query in Query_List:
		URL_Regex = re.search(r"(https?:\/\/(www\.)?)?([-a-zA-Z0-9@:%_\+~#=]{2,256})(\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?", Query)

		if URL_Regex:
			URL_Prefix = URL_Regex.group(1)
			URL_Body = URL_Regex.group(3)

			if URL_Regex.group(5) and URL_Regex.group(6):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

			elif URL_Regex.group(5):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

			else:
				URL_Extension = URL_Regex.group(4)

		else:
			sys.exit(str(datetime.datetime.now()) + " Please provide valid URLs.")

		for Extension in Generic_Extensions:

			if not URL_Extension == Extension:

				try:
					Query = URL_Body + Extension
					Web_Host = URL_Prefix.replace("s", "") + Query
					Response = socket.gethostbyname(Query)

					if Response:
						Cache = Query + ":" + Response

						if Cache not in Cached_Data and Cache not in Data_to_Cache:
							Valid_Results.append(Query + "," + Response)
							Data_to_Cache.append(Cache)
							Valid_Hosts.append(Web_Host)

				except Exception as e:
					print(str(datetime.datetime.now()) + e)

		URL_Domain = URL_Body + URL_Extension
		Output_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(Valid_Results), URL_Body, The_File_Extension)

		if Output_File:

			for Host in Valid_Hosts:
				General.Connections(Output_File, Query, Local_Plugin_Name, Host, URL_Domain, "Domain Spoof", Task_ID, General.Get_Title(Host))

	if Cached_Data:
		General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

	else:
		General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")

def Global_Extensions(Query_List, Task_ID):
	Local_Plugin_Name = Plugin_Name + "-Global-Suffixes"
	Data_to_Cache = []
	Cached_Data = []
	Valid_Results = ["Domain,IP Address"]
	Valid_Hosts = []
	Directory = General.Make_Directory(Concat_Plugin_Name)
	General.Logging(Directory, Local_Plugin_Name)
	Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

	if not Cached_Data:
		Cached_Data = []

	print(str(datetime.datetime.now()) + " Global Suffixes Selected.")
	Query_List = General.Convert_to_List(Query_List)

	for Query in Query_List:
		URL_Regex = re.search(r"(https?:\/\/(www\.)?)?([-a-zA-Z0-9@:%_\+~#=]{2,256})(\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?", Query)

		if URL_Regex:
			URL_Prefix = URL_Regex.group(1)
			URL_Body = URL_Regex.group(3)

			if URL_Regex.group(5) and URL_Regex.group(6):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

			elif URL_Regex.group(5):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

			else:
				URL_Extension = URL_Regex.group(4)

		else:
			sys.exit(str(datetime.datetime.now()) + " Please provide valid URLs.")

		for suffix in Global_Domain_Suffixes:

			if not URL_Extension == suffix:

				try:
					Query = URL_Body + suffix
					Web_Host = URL_Prefix.replace("s", "") + Query
					Response = socket.gethostbyname(Query)

					if Response:
						Cache = Query + ":" + Response

						if Cache not in Cached_Data and Cache not in Data_to_Cache:
							Valid_Results.append(Query + "," + Response)
							Data_to_Cache.append(Cache)
							Valid_Hosts.append(Web_Host)

				except Exception as e:
					print(str(datetime.datetime.now()) + e)

		URL_Domain = URL_Body + URL_Extension
		Output_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(Valid_Results), URL_Body, The_File_Extension)

		if Output_File:

			for Host in Valid_Hosts:
				General.Connections(Output_File, Query, Local_Plugin_Name, Host, URL_Domain, "Domain Spoof", Task_ID, General.Get_Title(Host))

	if Data_to_Cache:

		if Cached_Data:
			General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

		else:
			General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")
			
def All_Extensions(Query_List, Task_ID):
	Local_Plugin_Name = Plugin_Name + "-All-Extensions"
	Data_to_Cache = []
	Cached_Data = []
	Valid_Results = ["Domain,IP Address"]
	Valid_Hosts = []
	Directory = General.Make_Directory(Concat_Plugin_Name)
	General.Logging(Directory, Local_Plugin_Name)
	Cached_Data = General.Get_Cache(Directory, Local_Plugin_Name)

	if not Cached_Data:
		Cached_Data = []

	print(str(datetime.datetime.now()) + " All Extensions Selected.")
	Query_List = General.Convert_to_List(Query_List)

	for Query in Query_List:
		URL_Regex = re.search(r"(https?:\/\/(www\.)?)?([-a-zA-Z0-9@:%_\+~#=]{2,256})(\.[a-z]{2,3})(\.[a-z]{2,3})?(\.[a-z]{2,3})?", Query)

		if URL_Regex:
			URL_Prefix = URL_Regex.group(1)
			URL_Body = URL_Regex.group(3)

			if URL_Regex.group(5) and URL_Regex.group(6):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5) + URL_Regex.group(6)

			elif URL_Regex.group(5):
				URL_Extension = URL_Regex.group(4) + URL_Regex.group(5)

			else:
				URL_Extension = URL_Regex.group(4)

		else:
			sys.exit(str(datetime.datetime.now()) + " Please provide valid URLs.")

		for Extension in Generic_Extensions:

			for suffix in Global_Domain_Suffixes:
				suffix = suffix.replace(".com", "")
				suffix = suffix.replace(".co", "")

				if not URL_Extension == suffix:

					try:
						Query = URL_Body + Extension + suffix
						print(str(datetime.datetime.now()) + Query)
						Web_Host = URL_Prefix.replace("s://", "://") + Query
						Response = socket.gethostbyname(Query)

						if Response:
							Cache = Query + ":" + Response

							if Cache not in Cached_Data and Cache not in Data_to_Cache:
								Valid_Results.append(Query + "," + Response)
								Data_to_Cache.append(Cache)
								Valid_Hosts.append(Web_Host)

					except Exception as e:
						print(str(datetime.datetime.now()) + e)

		URL_Domain = URL_Body + URL_Extension
		Output_File = General.Main_File_Create(Directory, Local_Plugin_Name, "\n".join(Valid_Results), URL_Body, The_File_Extension)

		if Output_File:

			for Host in Valid_Hosts:
				General.Connections(Output_File, Query, Local_Plugin_Name, Host, URL_Domain, "Domain Spoof", Task_ID, General.Get_Title(Host))

		if Data_to_Cache:

			if Cached_Data:
				General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "a")

			else:
				General.Write_Cache(Directory, Data_to_Cache, Local_Plugin_Name, "w")
