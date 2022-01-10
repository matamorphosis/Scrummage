# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# Homograph Enumerator v2.0 (A.K.A Punycode Domain Fuzzer)

import itertools, logging, string, sys, plugins.common.Common as Common
from typing import List

class Iterator:

    def __init__(self, Query, English_Upper=False, Numbers=False, Special_Characters=False, Asian=False, Latin=False, Middle_Eastern=False, Native_American=False, North_African=False, Latin_Alternatives=False, Comprehensive=False):
        self.Query = Query
        self.English_Upper = English_Upper
        self.Numbers = Numbers
        self.Special_Characters = Special_Characters
        self.Asian = Asian
        self.Latin = Latin
        self.Middle_Eastern = Middle_Eastern
        self.Native_American = Native_American
        self.North_African = North_African
        self.Latin_Alternatives = Latin_Alternatives
        self.Comprehensive = Comprehensive

    def Search(self):
        Rotor_Wordlist = []
        Domain_Allowed_Characters_List = ['$', '-', '_', '.', '+', '!', '*', '\'', '(', ')', ',']

        if type(self.Query) == str:
            self.Query = list(self.Query)

        elif type(self.Query) != str and type(self.Query) != list:
            logging.error(f"{Common.Date()} [-] Invalid query type.")
            return None

        Lists = self.List_Formatter()

        for Letter in self.Query:

            for List_Key, List_Value in Lists.items():

                if Letter == List_Key:
                    Rotor_Wordlist.append(List_Value)

            for Character in Domain_Allowed_Characters_List:

                if Letter == Character:
                    Rotor_Wordlist.append(Character)

        return self.Rotor_Combinations(Rotor_Wordlist)

    def List_Formatter(self):
        Lists = {}
        Cyrillic = False
        Greek = False
        Lao = False
        Thai = False
        Korean = False
        Armenian = False
        Arabic = False
        Amharic = False
        Hebrew = False
        Georgian = False
        Khmer = False
        Burmese = False
        Vietnamese = False
        Tifinagh = False
        Vai = False
        Nko = False
        Cherokee = False
        Inuktitut = False
        Lisu = False
        Osmanya = False

        def Merger(Dict_to_Merge, Lists):

            for List_Key in Lists.keys():

                if List_Key in Dict_to_Merge:
                    Lists[List_Key].extend(Dict_to_Merge[List_Key])

            return Lists

        if self.Asian:
            Middle_Eastern = False
            Middle_Eastern_Alternatives = False
            Latin = False
            Latin_Alternatives = False
            Native_American = False
            English_Upper = False
            North_African = False
            Lao = True
            Thai = True
            Korean = True
            Khmer = True
            Burmese = True
            Vietnamese = True
            Lisu = True

        if self.Middle_Eastern:
            Asian = False
            Latin = False
            Latin_Alternatives = False
            Middle_Eastern_Alternatives = True
            Native_American = False
            English_Upper = False
            North_African = False
            Armenian = True
            Arabic = True
            Amharic = True
            Hebrew = True
            Georgian = True

        if self.North_African:
            Middle_Eastern = False
            Middle_Eastern_Alternatives = False
            Asian = False
            Latin = False
            Latin_Alternatives = False
            Native_American = False
            English_Upper = False
            Tifinagh = True
            Vai = True
            Nko = True
            Osmanya = True

        if self.Native_American:
            Asian = False
            Middle_Eastern = False
            Middle_Eastern_Alternatives = False
            Latin = False
            Latin_Alternatives = False
            English_Upper = False
            North_African = False
            Cherokee = True
            Inuktitut = True

        if self.Latin:
            Middle_Eastern = False
            Middle_Eastern_Alternatives = False
            Asian = False
            Latin_Alternatives = True
            Native_American = False
            English_Upper = False
            North_African = False
            Greek = True
            Cyrillic = True

        for Alphabet_Letter in list(string.ascii_lowercase):
            Lists[Alphabet_Letter] = [Alphabet_Letter]

            if self.English_Upper:
                Lists[Alphabet_Letter].append(Alphabet_Letter.upper())

        for Number in list(range(0,10)):
            Lists[str(Number)] = [str(Number)]

        Lists = Merger({"0": ["O", "o"], "1": ["l", "i", "I"], "2": ["Z", "z"], "3": ["E"], "4": ["A"], "5": ["S", "s"], "6": ["b"], "7": ["l", "T", "t", "Z", "z"], "8": ["B"], "9": ["q"]}, Lists)

        if self.Numbers:
            Lists = Merger({"a": ["4", u"Ꮞ"], "b": ["8", "6", u"Ꮾ", u"ꖉ", u"ꖊ"], "e": ["3", u"з", u"З", u"Ӡ", u"ဒ", u"ვ", u"ჳ", u"Ꮌ"], "i": ["1"], "l": ["1", u"ߗ"], "o": ["0", u"θ", u"០", u"៙", u"߀"], "s": ["5"], "t": ["7"], "z": ["2", u"ㄹ"]}, Lists)

        if self.Special_Characters:
            Lists = Merger({"a": ["@"], "b": ["ß"], "s": ["$"], "l": ["|", "[", "]"], "t": ["+"]}, Lists)

        if Cyrillic and self.Comprehensive:
            Lists = Merger({"a": [u"а", u"д"], "b": [u"в"], "c": [u"с"], "e": [u"е", u"є"], "h": [u"һ", u"Һ", u"ʜ"], "i": [u"і"], "k": [u"к"], "m": [u"м"], "n": [u"п", u"и", u"й", u"л"], "o": [u"о"], "p": [u"р"], "r": [u"г", u"я"], "s": [u"ѕ"], "t": [u"т"], "w": [u"ш", u"щ"], "x": [u"х", u"ж"], "y": [u"у", u"ү"]}, Lists)

        elif Cyrillic and not self.Comprehensive:
            Lists = Merger({"a": [u"а"], "c": [u"с"], "e": [u"е"], "h": [u"һ", u"Һ"], "i": [u"і"], "k": [u"к"], "m": [u"м"], "n": [u"п"], "o": [u"о"], "p": [u"р"], "r": [u"г"], "s": [u"ѕ"], "t": [u"т"], "w": [u"ш"], "x": [u"х"], "y": [u"у", u"ү"]}, Lists)

        if Greek and self.Comprehensive:
            Lists = Merger({"i": [u"ί", u"ι"], "k": [u"κ"], "n": [u"η", u"π"], "o": [u"ο", u"σ"], "p": [u"ρ"], "t": [u"τ"], "u": [u"υ"], "v": [u"ν", u"υ"], "w": [u"ω"], "x": [u"χ"], "y": [u"γ"]}, Lists)

        elif Greek and not self.Comprehensive:
            Lists = Merger({"k": [u"κ"], "n": [u"η"], "o": [u"ο", u"σ"], "p": [u"ρ"], "u": [u"υ"], "v": [u"ν"], "w": [u"ω"], "y": [u"γ"]}, Lists)

        if Armenian:
            Lists = Merger({"d": [u"ժ"], "g": [u"ց"], "h": [u"հ" u"ի"], "n": [u"ր", u"ռ", u"ո", u"ղ"], "o": [u"օ"], "p": [u"թ", u"բ", u"ք"], "q": [u"գ", u"զ"], "u": [u"ս", u"ն", u"մ"], "w": [u"ա", u"պ"]}, Lists)

        if Amharic:
            Lists = Merger({"h": [u"ከ", u"ኩ", u"ኪ", u"ካ", u"ኬ", u"ክ", u"ኮ", "ዘ", u"ዙ", u"ዚ", u"ዛ", u"ዜ", u"ዝ", u"ዞ", u"ዟ", u"ዠ", u"ዡ", u"ዢ", u"ዣ", u"ዤ", u"ዥ", u"ዦ", u"ዧ"], "l": [u"ገ", u"ጉ", u"ጊ", u"ጋ", u"ጌ", u"ግ", u"ጎ"], "m": [u"ጠ", u"ጡ", u"ጢ", u"ጣ", u"ጤ", u"ጦ", u"ጧ"], "n": [u"ሰ", u"ሱ", u"ሲ", u"ሳ", u"ሴ", u"ስ", u"ሶ", u"በ", u"ቡ", u"ቢ", u"ባ", u"ቤ", u"ብ", u"ቦ"], "o": [u"ዐ", u"ዑ", u"ዕ", u"ፀ", u"ፁ"], "p": [u"የ", u"ዩ", u"ዪ", u"ያ", u"ዬ", u"ይ", u"ዮ"], "t": [u"ፐ", u"ፑ", u"ፒ", u"ፓ", u"ፔ", u"ፕ", u"ፖ", u"ፗ"], "u": [u"ሀ", u"ሁ", u"ሆ", u"ህ"], "v": [u"ሀ", u"ሁ", u"ሆ"], "w": [u"ሠ", u"ሡ"], "y": [u"ሂ", u"ሃ"]}, Lists)

        if Arabic:
            Lists = Merger({"j": [u"ز"], "l": [u"ا", u"أ", u"آ"]}, Lists)

        if Hebrew:
            Lists = Merger({"i": [u"ו", u"נ", u"ו"], "l": [u"ן"], "n": [u"ח", u"ת", u"ה", u"תּ"], "o": [u"ס", u"ם"], "u": [u"ט"], "v": [u"ע"], "w": [u"ש", u"שׂ", u"שׁ"], "x": [u"א", u"ɣ"], "y": [u"צ", u"ץ"]}, Lists)

        if Burmese:
            Lists = Merger({"c": [u"င"], "h": [u"꧵"], "n": [u"ဂ"], "o": [u"ဝ"], "u": [u"ပ"], "w": [u"ယ"]}, Lists)

        if Khmer:
            Lists = Merger({"h": [u"អ"], "m": [u"ញ", u"៣"], "n": [u"ក", u"ព", u"ត", u"ភ", u"ឥ"], "s": [u"ន"], "u": [u"ឋ", u"ប", u"ឞ"], "w": [u"ឃ", u"យ", u"ដ", u"ផ"]}, Lists)

        if Korean:
            Lists = Merger({"c": [u"ㄷ"], "e": [u"ㅌ"], "l": [u"ㅣ", u"ㄴ"], "o": [u"ㅁ", u"ㅇ"], "t": [u"ㅜ", u'ㅊ']}, Lists)

        if Thai:
            Lists = Merger({"n": [u"ก", u"ค", u"ฅ", u"ฑ", u"ด", u"ต", u"ถ", u"ท", u"ห", u"ภ"], "u": [u"ข", u"ฃ", u"น", u"บ", u"ป"], "w": [u"ผ", u"ฝ", u"พ", u"ฟ", u"ฬ"]}, Lists)

        if Lao:
            Lists = Merger({"m": [u"ຕ", u"໘"], "n": [u"ດ", u"ກ", u"ຄ", u"ຖ"], "o": [u"໐"], "s": [u"ຣ", u"ຮ"], "u": [u"ນ", u"ບ", u"ປ", u"ມ"], "w": [u"ຜ", u"ຝ", u"ພ", u"ຟ", u"໖"]}, Lists)

        if Lisu: 
            Lists = Merger({"a": [u"ꓥ", u"ꓮ"], "b": [u"ꓐ"], "c": [u"ꓚ"], "d": [u"ꓒ", u"ꓓ"], "e": [u"ꓰ"], "f": [u"ꓝ"], "g": [u"ꓖ"], "h": [u"ꓧ"], "i": [u"ꓲ"], "j": [u"ꓙ"], "k": [u"ꓗ"], "l": [u"ꓡ", u"ꓲ"], "m": [u"ꓟ"], "n": [u"ꓠ", u"ꓥ", u"ꓵ"], "o": [u"ꓳ"], "p": [u"ꓑ"], "r": [u"ꓣ", u"ꓩ"], "s": [u"ꓢ"], "t": [u"ꓔ"], "u": [u"ꓴ"], "v": [u"ꓦ"], "w": [u"ꓪ"], "x": [u"ꓫ"], "y": [u"ꓬ"], "z": [u"ꓜ"]}, Lists)

        if Georgian:
            Lists = Merger({"b": [u"ხ", u"წ", u"Ⴆ"], "d": [u"ძ"], "h": [u"Ⴙ", u"ⴌ", u"ⴡ", u"ჩ"], "m": [u"ⴅ", u"ⴜ", u"ო", u"რ"], "n": [u"ⴄ", u"ⴈ", u"ი"], "t": [u"ⴕ"], "w": [u"ⴍ", u"ⴓ"], "x": [u"ⴟ"], "y": [u"ⴁ", u"ⴗ", u"ⴞ", u"ⴤ", u"ყ"]}, Lists)

        if Vietnamese or (self.Latin_Alternatives and self.Comprehensive):
            Lists = Merger({"a": [u"ắ", u"ậ", u"ả", u"ạ", u"ắ", u"ằ", u"ẳ", u"ẵ", u"ặ", u"ấ", u"ầ", u"ẩ", u"ẫ", u"ă", u"ą"], "d": [u"đ", u"d̪"], "i": [u"ị", u"ĩ", u"ỉ"], "e": [u"ệ", u"ế", u"ẻ", u"ẽ", u"ẹ", u"ề", u"ể", u"ễ", u"ĕ", u"ė", u"ę", u"ě"], "g": [u"ġ", u"ğ"], "n": [u"n̪", u"ŋ", u"ɲ"], "o": [u"ơ", u"ớ", u"ỏ", u"ố", u"ồ", u"ổ", u"ỗ", u"ộ", u"ờ", u"ở", u"ỡ", u"ŏ", u"ợ"], "s": [u"ş", u"s̠", u"ʂ"], "t": [u"t̪"], "u": [u"ư", u"ự", u"ữ", u"ủ", u"ụ", u"ứ", u"ừ", u"ử", u"ŭ", u"ů", u"ư"], "y": [u"ỹ", u"ỳ", u"ỷ", u"ỵ", u"ý"]}, Lists)

        if Inuktitut:
            Lists = Merger({"a": [u"ᐃ", u"ᐄ", u"ᐱ", u"ᐲ", u"ᕕ", u"ᕖ"], "d": [u"ᑯ", u"ᑰ", u"ᕷ", u"ᕸ"], "n": [u"ᑎ", u"ᑏ", u"ᐱ", u"ᐲ", u"ᕕ", u"ᕖ"], "j": [u"ᒍ", u"ᒎ", u"ᒧ", u"ᒨ", u"ᖑ", u"ᖒ"], "p": [u"ᑭ", u"ᑮ", u"ᕵ", u"ᕶ", u"ᕈ", u"ᕉ"], "r": [u"ᒋ", u"ᒌ", u"ᒥ", u"ᒦ"], "u": [u"ᕂ", u"ᑌ"], "v": [u"ᐁ", u"ᐯ", u"ᕓ"]}, Lists)

        if Tifinagh:
            Lists = Merger({"a": [u"ⵠ"], "c": [u"ⵎ", u"ⵛ", u"ⵞ", u"ⵦ"], "e": [u"ⴹ", u"ⵉ", u"ⵞ", u"ⵟ"], "h": [u"ⴼ", u"ⵄ", u"ⵍ"], "i": [u"ⵊ", u"ⵏ"], "k": [u"ⴽ", u"ⴿ"], "l": [u"ⵊ", u"ⵏ", u"ⵑ"], "n": [u"ⴷ", u"ⵍ"], "o": [u"ⴰ", u"ⴱ", u"ⴲ", u"ⵀ", u"ⵁ", u"ⵔ", u"ⵙ", u"ⵚ"], "q": [u"ⵕ", u"ⵚ"], "r": [u"ⵇ"], "s": [u"ⵢ"], "t": [u"ⴶ", u"ⵜ"], "u": [u"ⵡ"], "v": [u"ⴸ"], "x": [u"ⴳ", u"ⴴ", u"ⴵ", u"ⵅ", u"ⵋ", u"ⵝ", u"ⵣ", u"ⵥ"], "y": [u"ⵖ"], "z": [u"ⵒ"]}, Lists)

        if Vai:
            Lists = Merger({"a": [u"ꕔ", u"ꕖ"], "b": [u"ꕗ"], "e": [u"ꗋ", u"ꗍ", u"ꗨ", u"ꗩ"], "h": [u"ꖾ"], "k": [u"ꗣ"], "o": [u"ꕕ", u"ꔮ", u"ꖴ"], "s": [u"ꕶ", u"ꕷ", u"ꗟ"], "x": [u"ꖼ", u"ꖻ"]}, Lists)

        if Nko:
            Lists = Merger({"b": [u"ߕ"], "d": [u"߄", u"ߥ"], "f": [u"ߓ"], "l": [u"ߊ", u"ߗ", u"߁"], "n": [u"ߍ", u"ߡ"], "o": [u"ߋ", u"߀", u"ߛ", u"ߋ߫", u"ߋ߬", u"ߋ߭", u"ߋ߮", u"ߋ߯", u"ߋ߰", u"ߋ߱", u"ߋ߲", u"ߋ߳"], "q": [u"ߟ"], "t": [u"ߙ", u"ߠ"], "u": [u"ߎ"], "v": [u"߇", u"߈", u"ߜ"], "y": [u"ߌ‎"]}, Lists)

        if Osmanya:
            Lists = Merger({"b": [u"𐒑"], "c": [u"𐒛", u"𐒨"], "e": [u"𐒢"], "g": [u"𐒛"], "h": [u"𐒙", u"𐒅", u"𐒎", u"𐒚", u"𐒣"], "i": [u"𐒃", u"𐒗"], "o": [u"𐒆", u"𐒀", u"𐒤", u"𐒠"], "l": [u"𐒃", u"𐒊", u"𐒗"], "m": [u"𐒄", u"𐒝"], "n": [u"𐒐"], "s": [u"𐒖", u"𐒡"], "u": [u"𐒜", u"𐒩"], "w": [u"𐒁"], "y": [u"𐒍", u"𐒋", u"𐒔", u"𐒦"], "z": [u"𐒒"]}, Lists)

        if Middle_Eastern_Alternatives:
            Lists = Merger({"g": [u"ܦ݂", u"ܦ݂"], "o": [u"ܘ"], "v": [u"ݍ"]}, Lists)

        if Latin_Alternatives:
            Lists = Merger({"a": [u"à", u"á", u"â", u"ã", u"ä", u"å", u"ā"], "b": [u"þ", u"ɓ"], "c": [u"ç", u"ć", u"ĉ", u"ċ", u"č"], "d": [u"ð"], "e": [u"ē", u"è", u"é", u"ê", u"ë", u"ɛ", u"ɛ́", u"ɛ̃"], "h": [u"ɦ"], "i": [u"ì", u"í", u"î", u"ï", u"ɪ́", u"ɪ̃", u"ɪ̃́", u"ɪ̃"], "l": [u"ł", u"ɬ"], "m": ["rn"], "n": [u"ʎ", u"n̥"], "o": [u"ø", u"ó", u"ò", u"ô", u"õ", u"ö", u"ō", u"ɸ", u"ṍ"], "r": [u"ɾ"], "s": [u"š", u"ś"], "t": [u"ł"], "u": [u"ù", u"ú", u"û", u"ü", u"ũ", u"ū"], "v": [u"ʋ", u"ʊ"], "w": [u"ɰ", u"ɰ̃", u"w̃"], "y": [u"ÿ", u"ɣ"]}, Lists)

        if Cherokee:
            Lists = Merger({"a": [u"Ꭺ", u"Ꭿ"], "b": [u"Ᏼ", u"Ᏸ", u"Ꮟ"], "c": [u"Ꮸ", u"Ꮆ", u"Ꮯ", u"Ꮳ"], "d": [u"Ꭰ", u"Ꮝ", u"Ꮷ"], "e": [u"Ꮛ", u"Ꭼ"], "f": [u"Ꮀ", u"Ꭸ"], "g": [u"Ꮆ", u"Ᏻ", u"Ꮹ"], "h": [u"Ꮒ", u"Ꮋ", u"Ꮵ", u"Ᏺ"], "i": [u"Ꭵ", u"Ꮠ", u"Ꮖ"], "j": [u"Ꭻ"], "k": [u"Ꮶ"], "l": [u"Ꮭ", u"Ꮦ", u"Ꮮ", u"Ꮂ"], "m": [u"Ꮇ"], "n": [u"Ꮑ"], "o": [u"Ꭴ", u"Ꮊ", u"Ꮎ", u"Ꮕ", u"Ꭷ", u"Ꮻ"], "p": [u"Ꮅ", u"Ꭾ"], "r": [u"Ꭱ", u"Ꮡ", u"Ꮁ", u"Ꮢ"], "s": [u"Ꭶ", u"Ꮪ", u"Ꮥ"], "t": [u"Ꭲ", u"Ꮏ", u"Ꮱ", u"Ꮦ", u"Ꮘ"], "u": [u"Ꮰ", u"Ꮜ", u"Ꮺ", u"Ꮼ"], "v": [u"Ꮙ", u"Ꮴ", u"Ꮩ", u"Ꮺ", u"Ꮼ"], "w": [u"Ꮃ", u"Ꮤ", u"Ꮿ", u"Ꮗ", u"Ꮚ"], "y": [u"Ꭹ", u"Ꮍ"], "z": [u"Ꮓ"]}, Lists)

        return Lists

    def Rotor_Combinations(self, Rotor_Wordlist):

        if (len(Rotor_Wordlist) <= 15):
            Altered_URLs = list(map(''.join, list(itertools.product(*Rotor_Wordlist))))
            return Altered_URLs

        else:
            logging.warning(f"{Common.Date()} [-] The word entered was either over 15 characters in length or had no characters, this function only permits words with character lengths between 1 and 15.")
            return None