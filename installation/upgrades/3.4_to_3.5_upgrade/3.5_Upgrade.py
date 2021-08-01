#!/usr/bin/python3
import json, sys, os

try:

	def Inner_Values(Key, Current_Value):
		New_Value = {}

		for Inner_Key, Inner_Item in Current_Value.items():

			if not (Key == "youtube" and Inner_Key in ["location", "location_radius"]):
				New_Value[Inner_Key.lower().replace("-", "_")] = Inner_Item

		return New_Value

	New_Data = {"inputs": {}, "outputs": {}, "core": {}}
	Inputs = ["craigslist", "ebay", "emailrep", "flickr", "general", "google", "greynoisesearch", "haveibeenpwned", "hunter", "intelligencex", "ipstack", "naver", "ok", "pinterest", "reddit", "shodan", "sslmate", "tumblr", "twitter", "ukbusiness", "vkontakte", "virustotal", "vulners", "yandex", "youtube"]
	Outputs = ["csv", "docx_report", "defectdojo", "elasticsearch", "email", "jira", "postgresql", "rtir", "slack", "scumblr"]
	Core = ["web-scraping", "web-app", "google-chrome"]
	File = open("config.json", "r")
	JSON_Data = json.load(File)
	File.close()

	for Key, Value in JSON_Data.items():

		if Key.lower() in Inputs:
			Key = Key.lower().replace("-", "_")
			New_Data["inputs"][Key] = Inner_Values(Key, Value)

		elif Key.lower() in Outputs:
			Key = Key.lower().replace("-", "_")
			New_Data["outputs"][Key] = Inner_Values(Key, Value)

		elif Key.lower() in Core:
			Key = Key.lower().replace("-", "_")
			New_Data["core"][Key] = Inner_Values(Key, Value)

	New_Data["core"]["proxy"] = {"http": "", "https": "", "use_system_proxy": False}
	New_File = open("config_new.json", "w")
	New_File.write(json.dumps(New_Data, indent=2))
	New_File.close()

except Exception as e:
	print(f"[-] {str(e)}.")