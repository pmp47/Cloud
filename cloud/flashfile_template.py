#--start requirements--
#pip installs
import requests
from security import Encrypting

#customs

#builtins
import zlib
import zipfile
import os
from subprocess import call
from datetime import datetime

#--end requirements--

#REQUIRED VARIABLES (uncomment and replace )
#presigned_zip_urls = []
#passphrase = []
final_commands = []

env_dir = os.path.dirname(os.path.abspath(__file__))
dependancy_zip_filepath = env_dir + '/dependancy_package.zip'

def tprint(content: str):
	print(str(datetime.now()) + content)

for pzu in presigned_zip_urls:
	#download the dependancy zip, decrypt it, and uncompress it
	tprint(' -- Downloading ' + pzu + ' -- ')
	data = zlib.decompress(Encrypting.Symmetric.Decrypt(requests.get(presigned_dependancy_zip_url)._content,passphrase))

	#write the dependancy zip to a file on disk
	with open(dependancy_zip_filepath, 'wb') as file:
		file.write(data)

	#unzip the dependancy zip file
	tprint(' -- Unzipping ' + pzu + ' -- ')
	with zipfile.ZipFile(dependancy_zip_filepath, 'r') as zip_ref:
		zip_ref.extractall(env_dir)

#remove this flashfile
tprint(' -- Removing this flashfile -- ')
os.remove(os.path.abspath(__file__))

#remove the dependancy zip file
tprint(' -- Removing ' + dependancy_zip_filepath + ' -- ')
os.remove(dependancy_zip_filepath)

#run the final command
final_commands = list(filter(None, final_commands))
if len(final_commands) > 0:
	tprint(' -- Executing final commands -- ')
	
	#TODO: dont want to see output, should automatically return, no stream stdout

	call(final_commands)