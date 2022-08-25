import json, os, sys, requests, logging, base64, hashlib
from Crypto.Cipher import AES
from Crypto import Random
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
Current_User_Agent: str = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'

class Coder:

    def __init__(self, to_code):
        self.to_code = to_code

    def encode_check(self):

        if isinstance(self.to_code, bytes):
            self.to_code = self.to_code

        else:
            self.to_code = self.to_code.encode()

    def decode_check(self):

        if isinstance(self.to_code, str):
            self.to_code = self.to_code

        else:
            self.to_code = self.to_code.decode()

    def b64_encode(self):
        self.encode_check()
        return base64.b64encode(self.to_code).decode()

    def b64_urlsafe_encode(self):
        self.encode_check()
        return base64.urlsafe_b64encode(self.to_code).decode()

    def b64_decode(self, decode: bool=True):
        self.decode_check()

        if decode:
            return base64.b64decode(self.to_code).decode()

        else:
            return base64.b64decode(self.to_code)

    def b64_urlsafe_decode(self, decode):
        self.decode_check()

        if decode:
            return base64.urlsafe_b64decode(self.to_code).decode()

        else:
            return base64.urlsafe_b64decode(self.to_code)

class Cryptography:

    def __init__(self):
        """Initialises cryptography object"""
        BLOCK_SIZE = 16
        self.pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
        self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        self.filesystem_uuid = os.environ["DISK_UUID"]

        if self.filesystem_uuid is None:
            Message = "Environment Variables needed for cryptography don't exist."
            logging.warning(Message)
            raise ValueError(Message)

    def encrypt(self, raw):
        """Encrypts data"""
        private_key = hashlib.sha256(self.filesystem_uuid.encode("utf-8")).digest()
        raw = self.pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return Coder(iv + cipher.encrypt(raw.encode())).b64_encode()

    def decrypt(self, enc):
        """Decrypts data"""
        private_key = hashlib.sha256(self.filesystem_uuid.encode("utf-8")).digest()
        enc = Coder(enc).b64_decode(decode=False)
        iv = enc[:16]
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(enc[16:])).decode()

    def configuration_encrypt(self, configuration: dict() = dict()) -> str:
        """Encrypts configuration data"""
        return self.encrypt(JSON_Handler(configuration).Dump_JSON(Sort=False))

    def configuration_decrypt(self, encrypted_configuration: str = str()) -> dict:
        """Decrypts configuration data"""
        # Requires double JSON loading.
        return JSON_Handler(JSON_Handler(self.decrypt(encrypted_configuration)).To_JSON_Loads()).To_JSON_Loads()

class JSON_Handler:

    def __init__(self, raw_data):
        self.json_data = raw_data

    def Is_JSON(self):

        try:
            json_object = json.loads(self.json_data)

        except ValueError:
            return False

        return json_object

    def To_JSON_Load(self):

        try:
            self.json_data = json.load(self.json_data)
            return self.json_data

        except Exception as e:
            logging.error(f"Common Library - {str(e)}.") 

    def To_JSON_Loads(self):

        try:
            self.json_data = json.loads(self.json_data)
            return self.json_data

        except Exception as e:
            logging.error(f"Common Library - {str(e)}.")   

    def Dump_JSON(self, Indentation=2, Sort=True):

        try:

            if Indentation > 0:
                self.json_data = json.dumps(self.json_data, indent=Indentation, sort_keys=Sort)

            else:
                self.json_data = json.dumps(self.json_data, sort_keys=Sort)

            return self.json_data

        except Exception as e:
            logging.error(f"Common Library - {str(e)}.")

def Get_Relative_Configuration() -> set:
    Current_PWD: str = os.getcwd().lower()
    Configuration_File: str = str()
    DB_File: str = str()

    if Current_PWD.endswith("scrummage/installation"):
        Configuration_File = "../app/plugins/common/config/config.config"
        DB_File = "../app/plugins/common/config/db.config"

    if Current_PWD.endswith("support_files"):
        Configuration_File = "../../app/plugins/common/config/config.config"
        DB_File = "../../app/plugins/common/config/db.config"

    elif Current_PWD.endswith("scrummage"):
        Configuration_File = "./app/plugins/common/config/config.config"
        DB_File = "./app/plugins/common/config/db.config"

    elif Current_PWD.endswith("scrummage/app"):
        Configuration_File = "./plugins/common/config/config.config"
        DB_File = "./plugins/common/config/db.config"

    elif Current_PWD == "/":
        Configuration_File = "/Scrummage/app/plugins/common/config/config.config"
        DB_File = "/Scrummage/app/plugins/common/config/db.config"

    else:
        sys.exit("[!] - [FATAL ERROR] - failed to determine relative or absolute path.")

    return Configuration_File, DB_File