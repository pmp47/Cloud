#--start requirements--
#pip installs
from security import Encrypting, Hashing

#customs
from containers import Docker, Linux
from remotenodes import ComputeTask, ComputeCluster, Communication, HardenedNode
from dictableobj import DictableObj
from wasabi_service import Wasabi
from aws_service import AWS
from digitalocean_service import DigitalOcean

#builtins
import json
import zipfile
import os
import decimal
import time
from datetime import datetime
from multiprocessing.dummy import Pool as MultiThreading
import functools

#--end requirements--

def replace_decimals(obj: object):
	"""Replaces all attributes in the object that are type (Decimal) as either (int) or (float).
	Args:
		obj (object): Object to replace Decimals in.
	Returns:
		object: obj
	Ref:
		https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GettingStarted.Python.04.html
	"""
	if isinstance(obj, list):
		for i in range(len(obj)):
			obj[i] = replace_decimals(obj[i])
		return obj
	elif isinstance(obj, dict):
		for k in list(obj.keys()):
			obj[k] = replace_decimals(obj[k])
		return obj
	elif isinstance(obj, decimal.Decimal):
		if obj % 1 == 0:
			return int(obj)
		else:
			return float(obj)
	elif isinstance(obj, set):
		return list(obj)
	else:
		return obj

def enforce_decimals(obj: object):
	"""Enforce required (Decimal) formatting of the object's attributes by replace (float) and (int) types.
	Args:
		obj (object):
	Returns:
		object: obj
	"""
	if isinstance(obj, list):
		for i in range(len(obj)):
			obj[i] = enforce_decimals(obj[i])
		return obj
	elif isinstance(obj, dict):
		for k in list(obj.keys()):
			obj[k] = enforce_decimals(obj[k])
		return obj
	elif isinstance(obj, float):
		return decimal.Decimal(str(obj))
	elif isinstance(obj, int):
		if isinstance(obj, bool):
			return obj #decimal.Decimal(str(int(obj)))
		else:
			return decimal.Decimal(str(obj))
	elif isinstance(obj, set):
		return list(obj)
	else:
		return obj

class LambdaConfig(DictableObj):
	"""Configuration object for a serverless Lambda function.
	Args:
		func_name (str): Name to identify serverless function.
		func_handler (str): Name of defined function to be the handler/entry.
		purpose (str): A description with an intention.
		role_name (str): IAM role name for the funcion to assume.
		func_filepath (str):  Local filepath of main script with has the lambda_handler function.
		environment_name (str): Foldername to package this serverless environment.
		mem (int): VRAM to use in MB, must be divisible by 64.
		timeout (int): Seconds until function exits whether it has completed or not.
		overwrite (bool): True to overwrite the current serverless function specified by this name.
		runtime (str): 'python2.7' | 'python3.6'
		pip_requirements_list (list): List of pip installations like requirements.txt.
		sup_Filepaths_list (list): List of supplimentary filepaths to include.
	"""
	def __init__(self,kwargs):

		self.func_name = kwargs['func_name']
		self.func_handler = kwargs['func_handler']
		self.purpose = kwargs['purpose']
		self.role_name = kwargs['role_name']
		self.func_filepath = kwargs['func_filepath']
		self.environment_name = kwargs['environment_name']
		self.mem = kwargs['mem']
		self.timeout = kwargs['timeout']
		self.overwrite = kwargs['overwrite']
		self.runtime = kwargs['runtime']
		self.pip_requirements_list = kwargs['pip_requirements_list']
		self.sup_Filepaths_list = kwargs['sup_Filepaths_list']

		return super().__init__()

class ApiConfig(DictableObj):
	"""Configuration for an API gateway.
	Args:
		api_name (str):
		purpose (str):
		usage_name (str):
		usage_purpose (str):
		usage_throttle_rate (float):
		usage_throttle_burst (int):
		usage_quota_limit (int):
		usage_quota_period (str): 'DAY' | 'WEEK' | 'MONTH'
		usage_quota_offset (int): 
		key_name (str):
		key_purpose (str):
		resource_name (str):
		http_method (str): 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS'|'ANY'
		stage_name (str):
		stage_purpose (str):
		deployment_purpose (str):

	"""
	def __init__(self,kwargs):

		self.api_name = kwargs['api_name']
		self.purpose = kwargs['purpose']
		self.usage_name = kwargs['usage_name']
		self.usage_purpose = kwargs['usage_purpose']
		self.usage_throttle_rate = kwargs['usage_throttle_rate']
		self.usage_throttle_burst = kwargs['usage_throttle_burst']
		self.usage_quota_limit = kwargs['usage_quota_limit']
		self.usage_quota_period = kwargs['usage_quota_period']
		self.usage_quota_offset = kwargs['usage_quota_offset']
		self.key_name = kwargs['key_name']
		self.key_purpose = kwargs['key_purpose']
		self.resource_name = kwargs['resource_name']
		self.http_method = kwargs['http_method']
		self.stage_name = kwargs['stage_name']
		self.stage_purpose = kwargs['stage_purpose']
		self.deployment_purpose = kwargs['deployment_purpose']

		return super().__init__()

class ClusterConfig(DictableObj):
	"""Configuration object for a compute cluster.
	Args:
		tag (str): Unique identifying tag for this cluster.
		n_nodes (int): Number of individual compute nodes to deploy.
		compute_task (dict):
		asymKeys (dict): Asymmetric key pair for SSH communication.
		OSimage (str): Image identified by string for service such as 'docker-18-04' for docker installed ubuntu on DO
		price_per_node (int): Dollar per month per node (for helping managing costs)
		useMonitoring (bool): For turning on DO monitoring (dont use yet?)
		runtime (str): Python runtime identifyer such as 'python3.6'
		pip_requirements_list (list):
		sup_Filepaths_list (list):
	"""

	def __init__(self,kwargs):

		self.tag = kwargs['tag']
		self.n_nodes = kwargs['n_nodes']
		self.compute_task = kwargs['compute_task']
		self.asymKeys = kwargs['asymKeys']
		
		self.OSimage = kwargs['OSimage']
		self.price_per_node = kwargs['price_per_node']
		
		self.useMonitoring = kwargs['useMonitoring']

		self.runtime = kwargs['runtime']
		self.pip_requirements_list = kwargs['pip_requirements_list']
		self.sup_Filepaths_list = kwargs['sup_Filepaths_list']

		return super().__init__()

	def List_OS_images():
		pass

class CloudManager:
	"""Managing class for abstract cloud service operations.
	"""

	class NoSQLDatabase:
		"""Managed NoSQL database cloud service.
		Notes:
			Currently uses AWS DynamoDB.
			Generally used for very small (1kB?) objects that require fast reading/writing.
		"""

		class Condition(DictableObj):
			"""Condition for a database query.
			Args:
				hash_key_name (str): Name of the attribute that is the hash key.
				hash_key_val (?): Value of the hash attribute 
				hash_op (str): Must always be '='
				range_key_name (str): Name of the attribute that is the range key.
				range_key_val (?): Value of the range key comparison.
				range_op (str): Operation to apply for the range key -> 'begins_with' | 'between' | '=' | '<' | '<=' | '>' | '>='
			"""
			def __init__(self,hash_key_name='ID',hash_key_val='001',hash_op='=',range_key_name='date',range_key_val='0',range_op='begins_with'):

				#configure the seesion via credentials
				self.hash_key_name = hash_key_name if hash_key_name != 'ID' else hash_key_name
				self.hash_key_val = hash_key_val if hash_key_val != '001' else hash_key_val
				self.hash_op = hash_op if hash_op != '=' else hash_op

				self.range_key_name = range_key_name if range_key_name != 'date' else range_key_name
				self.range_key_val = range_key_val if range_key_val != '0' else range_key_val
				self.range_op = range_op if range_op != 'begins_with' else range_op

				return super().__init__()

		def Write(obj_as_dict: dict,tablename: str,creds='',isLocalTest=False):
			"""Write obj to database.
			Args:
				obj_as_dict (dict): Object to write in dict format.
				tablename (str): Name of database table that already exists.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Response from database service.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			obj_as_dict = enforce_decimals(obj_as_dict)
			return AWS.DynamoDB.Write(dynamodb,obj_as_dict,tablename)

		def BatchWrite(obj_list: list,tablename: str,creds='',isLocalTest=False):
			"""Batch write objects to database.
			Args:
				obj_list (list): List of objects to write in dict format.
				tablename (str): Name of database table that already exists.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Response from database service.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			obj_list = enforce_decimals(obj_list)
			return AWS.DynamoDB.BatchWrite(dynamodb,obj_list,tablename)

		def Read(keys: dict,tablename: str,creds='',isLocalTest=False):
			"""Read obj from database.
			Args:
				keys (dict): Keys of object to designate for reading -> {'hash_att': 'hash_val'}
				tablename (str): Name of database table where object was written.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Object as a dict.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			ret_obj = AWS.DynamoDB.Read(dynamodb,keys,tablename)
			return replace_decimals(ret_obj)

		def ChangeKeyValues(obj_as_dict: dict,tablename: str,key_definitions: dict,new_vals: list,creds='',isLocalTest=False):
			"""Change the key values of an object in the database.
			Args:
				obj_as_dict (dict): Object to write in dict format.
				tablename (str): Name of database table that already exists.
				key_definitions (dict): { 'hash': ['hashattr','S'],'range': ['rangeattr','N']}
				new_vals (list): [new_hash_val,new_range_val], None for not changing
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Object as a dict.
			"""

			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			obj_as_dict = enforce_decimals(obj_as_dict)
			new_vals = enforce_decimals(new_vals)
			try:
				if isLocalTest:
					obj_keys = {}
					obj_keys[key_definitions['hash'][0]] = obj_as_dict[key_definitions['hash'][0]]
					if key_definitions['range'] != None:
						obj_keys[key_definitions['range'][0]] = obj_as_dict[key_definitions['range'][0]]

					del_worked = CloudManager.Erase(obj_keys,tablename,creds=creds,isLocalTest=isLocalTest)
					if (new_vals[0] != None):
						obj_as_dict[key_definitions['hash'][0]] = new_vals[0]
					if (new_vals[1] != None):
						obj_as_dict[key_definitions['range'][0]] = new_vals[1]
					write_resp = CloudManager.Write(obj_as_dict,tablename,creds=creds,isLocalTest=isLocalTest)

					return ((write_resp['ResponseMetadata']['HTTPStatusCode'] == 200) == del_worked)
				else:
					response = AWS.DynamoDB.ChangeKeyValue(dynamodb,obj_as_dict,tablename,key_definitions,new_vals)
					return response['ResponseMetadata']['HTTPStatusCode'] == 200
			except Exception as ex:

				#if is local will fail because not currenlty supported, change to a delete then write?

				#TODO: current issue:
				#raises ValidationException
				#Transaction request cannot include multiple operations on one item
				#this occurs if the item's new vals are not different from current
				#

				#return False
				raise ex

		def Query(tablename: str,condition: dict,creds='',isLocalTest=False):
			"""Query objects from database.
			Args:
				tablename (str): Name of database table where object was written.
				condition (dict): CloudManager.Condition().Dictify() for default query condition.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				list: List of objects as dicts.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			condition = enforce_decimals(condition)
			ret_obj = AWS.DynamoDB.Query(dynamodb,condition,tablename)
			return replace_decimals(ret_obj)['Items']

		def Erase(keys: dict,tablename: str,creds='',isLocalTest=False):
			"""Erase obj from database.
			Args:
				keys (dict): Keys of object to designate for deletion -> {'hash_att': 'hash_val'}
				tablename (str): Name of database table where object was written.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				bool: True if HTTP successful.
			"""
			#TODO: change from keys to obj_as_dict like write?
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			keys = enforce_decimals(keys)
			response = AWS.DynamoDB.Erase(dynamodb,keys,tablename)
			return response['ResponseMetadata']['HTTPStatusCode'] == 200

		def List_Tables(creds='',isLocalTest=False):
			"""List all tables in database.
			Args:
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				list: tables
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			return AWS.DynamoDB.Table.List(dynamodb)

		def Create_Table(tablename: str,key_definitions: dict,creds='',isLocalTest=False):
			"""Create table in database.
			Args:
				tablename (str): Name of database table to create.
				key_definitions (dict): { 'hash': ['hashattr','S'],'range': ['rangeattr','N']}
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Response from database service.
			TODO:
				Add in ttl_attribute during creation if possible.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)

			hashkey = key_definitions['hash'][0]
			hashkey_type = key_definitions['hash'][1]
			if key_definitions['range'] != None:
				rangekey = key_definitions['range'][0]
				rangekey_type = key_definitions['range'][1]

			return AWS.DynamoDB.Table.Create(dynamodb,tablename,hashkey,hashkey_type=hashkey_type,rangekey_type=rangekey_type,rangekey=rangekey)

		def Update_Table_TTL(tablename: str,enabled=False,attributename='',creds='',isLocalTest=False):
			"""Update table time-to-lose feature.
			Args:
				tablename (str): Name of database table to update.
				enabled (bool): True if TTL is to be set as enabled.
				attributename (str): Name of TTL epoch attribute.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Response from database service.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			return AWS.DynamoDB.Table.UpdateTTL(dynamodb,tablename=tablename,enabled=enabled,attributename=attributename)

		def Delete_Table(tablename: str,creds='',isLocalTest=False):
			"""Delete table from database.
			Args:
				tablename (str): Name of database table to delete.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				dict: Response from database service.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			return AWS.DynamoDB.Table.Delete(dynamodb,tablename)

		def Scan_Table(tablename: str,creds='',isLocalTest=False):
			"""Scan all objects from a table in the database.
			Args:
				tablename (str): Name of database table to scan.
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				list: List of objects as dicts.
			Notes:
				Warning: High throughput operation.
			"""
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			return replace_decimals(AWS.DynamoDB.Table.Scan(dynamodb,tablename))
	
		def Confirm_Table(tablename: str,key_definitions: dict,creds='',isLocalTest=False):
			"""Confirm a table has specified key sceme
			Args:
				tablename (str): Specified table to confirm the schema of
				key_definitions (dict): { 'hash': ['hashattr','S'],'range': ['rangeattr','N']}
				creds (dict): Credentials for the service.
				isLocalTest (bool): Whether to use a local database engine for testing.
			Returns:
				bool: is_confirmed
			"""
		
			dynamodb = AWS.DynamoDB(creds,isLocalTest)
			resp = AWS.DynamoDB.Table.Describe(dynamodb,tablename)

			try:
				key_definitions['hash'][0]
				key_definitions['hash'][1]
			except:
				raise ValueError('key_definitions must have hash, range can be None')

			#see if HASH in keyscheme is the same attribute as in the provided key_definitions
			for keyscheme in resp['KeySchema']:
				if keyscheme['KeyType'] == 'HASH':
					if key_definitions['hash'][0] != keyscheme['AttributeName']:
						return False #different attribute
		
			#see if hash attribute has the specified type
			for attdef in resp['AttributeDefinitions']:
				if attdef['AttributeName'] == key_definitions['hash'][0]:
					if attdef['AttributeType'] != key_definitions['hash'][1]:
						return False #wrong type

			if key_definitions['range'] == None:
				return True

			#see if RANGE in keyscheme is the same attribute as in the provided key_definitions
			for keyscheme in resp['KeySchema']:
				if keyscheme['KeyType'] == 'RANGE':
					if key_definitions['range'][0] != keyscheme['AttributeName']:
						return False #different attribute
		
			#see if hash attribute has the specified type
			for attdef in resp['AttributeDefinitions']:
				if attdef['AttributeName'] == key_definitions['range'][0]:
					if attdef['AttributeType'] != key_definitions['range'][1]:
						return False #wrong type

			return True

	class ObjectStorage:
		"""For storing objects using a cloud service provider.
		Notes:
			Currently uses Wasabi.
			Generally used for larger objects (4kB+?) with slow read/write requirement.
		"""
		#TODO: creater router so can provide AWS s3 creds instead
		default_service_provider = 'wasabi'

		#TODO: list buckets?

		def Exists(bucketname: str,objectname: str,creds=''):
			"""Check if object already exists.
			Args:
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
			Returns:
				bool: exists
			"""
			return Wasabi.Object.Exists(Wasabi(creds),bucketname,objectname)

		def BatchExists(bucketnames: list,objectnames: list,creds=''):
			"""Check if object already exists.
			Args:
				bucketnames (list): List of specified buckets.
				objectnames (list): List of specifed objectnames.
				creds (dict): Credentials for the service.
			Returns:
				list: these_exist
			"""

			wasabi = Wasabi(creds)
			def ExistWrapper(exists_tuples):
				return Wasabi.Object.Exists(wasabi,exists_tuples[0],exists_tuples[1])

			exists_tuples = []
			for o in range(len(bucketnames)):
				exists_tuples.append((bucketnames[o],objectnames[o]))

			threadpool = MultiThreading()
			return threadpool.map(ExistWrapper,exists_tuples)
		
		def ListObjects(bucketname: str,folderpath: str,creds=''):
			"""List objects inside a bucket.
			Args:
				bucketname (str): Name of specified bucket.
				folderpath (str): Relative folderpath to list objects in (like objectname without the final specifier).
				creds (dict): Credentials for the service.
			Returns:
				list: objects_in_bucket
			"""
			try:
				return Wasabi.Bucket.ListDir(Wasabi(creds),bucketname,folderpath)
			except Exception as ex:
				return []

		def Upload(obj_as_str: str,bucketname: str,objectname: str,creds=''):
			"""Upload an in memory object represented as a string.
			Args:
				obj_as_str (str): An object represented as a string (such as json).
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""
			return Wasabi.Object.Upload(Wasabi(creds),obj_as_str,bucketname,objectname)

		def BatchUpload(objs_as_strs: list,bucketnames: list,objectnames: list,creds=''):
			"""Upload many objects using multithreading.
			Args:
				obj_as_strs (list): List of objects represented as strings.
				bucketnames (list): List of buckets.
				objectnames (list): List of objectnames.
				creds (dict): Credentials for the service.
			Returns:
				list: List of responses from server
			Notes:
				All list arguments will correspond to each other -> obj_as_strs[0] is specified by bucketnames[0] and objectnames[0].
			"""
			wasabi = Wasabi(creds)

			def UploadWrapper(upload_tuples):
				return Wasabi.Object.Upload(wasabi,upload_tuples[0],upload_tuples[1],upload_tuples[2])

			upload_tuples = []
			for o in range(len(objs_as_strs)):
				upload_tuples.append((objs_as_strs[o],bucketnames[o],objectnames[o]))

			threadpool = MultiThreading()
			responses = threadpool.map(UploadWrapper,upload_tuples)
			return responses

		def UploadFile(filePath: str,bucketname: str,objectname: str,creds='',forgetFileSecurity=False):
			"""Upload a file specified by local filepath.
			Args:
				filePath (str): Local absolute filepath of specified file.
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
				forgetFileSecurity (bool): True to suppress warning about uploading an unencrypted file.
			Returns:
				dict: server_response
			"""
			if not forgetFileSecurity: raise ValueError('Dangerous as file may be unencrypted - think of this as a copy into cloud')
			return Wasabi.Object.UploadFile(Wasabi(creds),filePath,bucketname,objectname)

		def Download(bucketname: str,objectname: str,creds='',decodeBytes=True):
			"""Download an object.
			Args:
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
				decodeBytes (bool): True to automatically decode returned raw bytes.
			Returns:
				str: if decodeBytes
					or
				bytes: if not decodeBytes
			"""
			raw_bytes = Wasabi.Object.Download(Wasabi(creds),bucketname,objectname)
			if decodeBytes:
				return raw_bytes.decode('utf-8')
			else:
				return raw_bytes

		def BatchDownload(bucketnames: list,objectnames: list,creds='',decodeBytes=True):
			"""Download many objects using multithreading.
			Args:
				bucketnames (list): List of specified buckets.
				objectnames (list): List of specifed objectnames.
				creds (dict): Credentials for the service.
				decodeBytes (bool): True to automatically decode returned raw bytes.
			Returns:
				list(str): if decodeBytes
					or
				list(byte): if not decodeBytes
			"""

			wasabi = Wasabi(creds)

			def DownloadWrapper(download_tuples):
				return Wasabi.Object.Download(wasabi,download_tuples[0],download_tuples[1])

			download_tuples = []
			for o in range(len(bucketnames)):
				download_tuples.append((bucketnames[o],objectnames[o]))

			threadpool = MultiThreading()
			raw_bytes = threadpool.map(DownloadWrapper,download_tuples)
			if decodeBytes:
				decoded_bytes = []
				for raw_byte in raw_bytes:
					decoded_bytes.append(raw_byte.decode('utf-8'))
				return decodeBytes
			else:
				return raw_bytes

		def Rename(old_bucketname: str,old_objectname: str,new_objectname: str,creds='',overwrite=False,quiet=False,folders=False):
			"""Rename an object.
			Args:
				old_bucketname (str): Current specified bucketname.
				old_objectname (str): Current specified objectname.
				new_objectname (str): Name objectname to be renamed to.
				creds (dict): Credentials for the service.
				overwrite (bool): False to prevent renaming to an already existing object.
				quiet (bool): Causes the XML status return body to only display the keys that encounter errors.
				folders (bool): False to only rename the objects (including all ver­sions) that exactly match the key.
			Returns:
				bool: was_renamed
			Notes:
				Cannot change bucketname.
				This renaming is specific to Wasabi and will not function properly with AWS's S3.
			"""
			resp = Wasabi.Object.Rename(Wasabi(creds),old_bucketname,old_objectname,new_objectname,overwrite,quiet,folders)
			return resp['ResponseMetadata']['HTTPStatusCode'] == 200

		def BatchRename(old_bucketnames: list,old_objectnames: list,new_objectnames: list,creds='',overwrite=False,quiet=False,folders=False):
			"""Rename multiple objects using multithreading.
			Args:
				old_bucketnames (list): List of current bucketnames.
				old_objectnames (list): List of current objectnames.
				new_objectnames (list): List of new objectnames.
				creds (dict): Credentials for the service.
				overwrite (bool): False to prevent renaming to an already existing object.
				quiet (bool): Causes the XML status return body to only display the keys that encounter errors.
				folders (bool): False to only rename the objects (including all ver­sions) that exactly match the key.
			Returns:
				list(bool): these_were_renamed
			Notes:
				Batch rename is limited due to the exceptions?
			"""
			wasabi = Wasabi(creds)

			def RenameWrapper(old_then_new_bucket_and_objectname_tuple: tuple):
				return Wasabi.Object.Rename(wasabi,\
					old_then_new_bucket_and_objectname_tuple[0],\
					old_then_new_bucket_and_objectname_tuple[1],\
					old_then_new_bucket_and_objectname_tuple[2],
					overwrite,quiet,folders)

			old_then_new_bucket_and_objectname_tuple = []
			for f in range(len(old_objectnames)):
				old_then_new_bucket_and_objectname_tuple.append((old_bucketnames[f],old_objectnames[f],new_objectnames[f]))

			threadpool = MultiThreading()
			resps = threadpool.map(RenameWrapper,old_then_new_bucket_and_objectname_tuple)
			isChangeds =[]
			for resp in resps:
				isChangeds.append(resp['ResponseMetadata']['HTTPStatusCode'] == 200)
			return isChangeds

		def ListBuckets(creds=''):
			"""List all buckets.
			Args:
				creds (dict): Credentials for the service.
			Returns:
				list: buckets
			"""
			wasabi = Wasabi(creds)

			resp = Wasabi.Bucket.List(wasabi)

			return resp['Buckets']

		def CreateBucket(bucketname: str,creds=''):
			"""Create a bucket.
			Args:
				bucketname (str): Name of specified bucket.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""
			return Wasabi.Bucket.Create(Wasabi(creds),bucketname)

		def DeleteBucket(bucketname: str,creds=''):
			"""Delete a bucket.
			Args:
				bucketname (str): Name of specified bucket.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""
			wasabi = Wasabi(creds)

			#must delete all items in a bucket before the bucket can be deleted
			obj_resp = Wasabi.Bucket.ListObjects(wasabi,bucketname)
			
			objects = []
			for obj in obj_resp['Contents']:
				objects.append({'Key':obj['Key']})
			resp = Wasabi.Bucket.Empty(wasabi,bucketname,{'Objects':objects})

			return Wasabi.Bucket.Delete(wasabi,bucketname)

		def Get_Upload_Url(bucketname: str,objectname: str,creds='',expiresec=100):
			"""Get Url for presigned object upload.
			Args:
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
				expiresec (int): Seconds until this presignation expires.
			Returns:
				dict: presigned_post_config
			"""
			return Wasabi.Object.Generate_Upload_Url(Wasabi(creds),bucketname,objectname,expiresec=expiresec)

		def Get_Download_Url(bucketname: str,objectname: str,creds='',expiresec=100):
			"""Get Url for presigned object download.
			Args:
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
				expiresec (int): Seconds until this presignation expires.
			Returns:
				str: presigned_GET_url
			"""
			return Wasabi.Object.Generate_Download_Url(Wasabi(creds),bucketname,objectname,expiresec=expiresec)

		def Delete(bucketname: str,objectname: str,creds=''):
			"""Delete an object.
			Args:
				bucketname (str): Name of specified bucket.
				objectname (str): Name of specified object, may contain '/' prefixes like a relative filepath.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""
			return Wasabi.Object.Delete(Wasabi(creds),bucketname,objectname)

		def BatchDelete(bucketname: str,objectnames: list,creds=''):
			"""Batch delete objects in a bucket.
			Args:
				bucketname (str): Name of specified bucket.
				objectnames (list): List of specified objectnames.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""
			objects = [{'Key': obj} for obj in objectnames]
			return Wasabi.Bucket.Empty(Wasabi(creds),bucketname,{'Objects': objects})

	
	class ServerlessFunctions:
		"""For utilizing serverless micro computing cloud services.
		Ref:
			https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html
		TODO:
			Add in azure
		"""

		def Summary(creds=''):
			"""Summarize deployed serverless functions.
			Args:
				creds (dict): Credentials for the service.
			Returns:
				dict: summary
			"""
			resp = AWS.Lambda(creds).Summary()
			return resp

		def List(creds=''):
			"""List the serverless functions deployed.
			Args:
				creds (dict): Credentials for the service.
			Returns:
				list: serverless_functions
			"""
			resp = AWS.Lambda(creds).List()

			return resp

		def Deploy(lambda_config: LambdaConfig,api_config=None,creds=''):
			"""Deploy a function to cloud serverless architecture.
			Args:
				lambda_config (LambdaConfig): The configuration for deployment.
				api_config (ApiConfig): If provided configures for granting API endpoint access.
				creds (dict): Credentials for the service.
			Returns:
				dict: lambda_creation_response
				dict: api_creation_response
			Notes:
				Requires Docker running locally in order to compile deployment package.
				The IAM role to be used must already exist.
				Currently API Gateway setup through ApiConfig is untested.
			"""
			
			#get the IAM role this function is to assume
			role_list = AWS.IAM.Role.List(AWS.IAM(creds))
			role = next((x for x in role_list if x['RoleName'] == lambda_config.role_name), None)
			if role is None:
				raise ValueError('Role doesnt exist')
			else:
				#TODO:requires at minimum, should have policies already attached for cloudwatch, should check here
				role_arn = role['Arn']

			#package the server deployment environment using a docker image
			dependancy_zip_filePath = Docker.Compile(
				lambda_config.environment_name,
				AWS.Lambda.image,
				pip_requirements_list=lambda_config.pip_requirements_list)

			if dependancy_zip_filePath is None:
				#was none because no requirements so make dummy zip file for adding supplimentary/main files
				dependancy_zip_filePath = lambda_config.func_filepath.split('.')[0] + '.zip'

			#add lambda func deployment
			lambda_creation_response = AWS.Lambda(creds).Create(
				lambda_config.func_name,
				lambda_config.purpose,
				lambda_config.runtime,
				lambda_config.func_filepath,
				dependancy_zip_filePath,
				role_arn,
				sup_Filepaths_list=lambda_config.sup_Filepaths_list,
				fcn_handler=lambda_config.func_handler,
				mem=lambda_config.mem,
				timeout=lambda_config.timeout,
				overwrite=lambda_config.overwrite)

			#if api_config supplied, plug into api
			api_creation_response = None
			if api_config is not None:

				api_creation_response = CloudManager.ServerlessFunctions.Utils.Create_rest_api(\
					api_config,lambda_creation_response[0]['FunctionName'],creds=creds)

			return lambda_creation_response,api_creation_response

		def Invoke(fcn_name: str,event: dict,creds=''):
			"""Invoke a serverless function.
			Args:
				fcn_name (str): Function specified by name.
				event (dict): json dict of payload.
				creds (dict): Credentials for the service.
			Returns:
				dict: response from function in json payload?
			"""
			return AWS.Lambda(creds).Invoke(fcn_name,event)

		class Utils:

			def Create_rest_api(api_config: ApiConfig,fcn_name: str,creds=''):
				"""Create a RESTful API to expose a serverless function.
				Args:
					api_config (ApiConfig):
					fcn_name (str): Function specified by name.
					creds (dict): Credentials for the service.
				Returns:
					dict: api_creation_response
				"""

				#create api client
				apig = AWS.APIGateway(creds)

				#instiate lambda, list functions, and get ARN if exists
				lmb = AWS.Lambda(creds)
				lambdas = lmb.List()

				function_arns = [x['FunctionArn'] for x in lambdas if x['FunctionName'] == fcn_name]
				if len(function_arns) != 1:
					raise ValueError('function specified by name not found/no arn')
				else:
					function_arn = function_arns[0]

				#create api itself
				api_creation_response = AWS.APIGateway.Create(apig,api_config.api_name,api_config.purpose,\
					overwrite=True,rest_type='REGIONAL',apikeysource='HEADER')

				#create usage plan
				usageplan_response = AWS.APIGateway.UsagePlan.Create(apig,api_config.usage_name,api_config.usage_purpose,\
					overwrite=True,throttle_rate=api_config.usage_throttle_rate,throttle_burst=api_config.usage_throttle_burst,\
					quota_limit=api_config.usage_quota_limit,quota_period=api_config.usage_quota_period,\
					quota_offset=api_config.usage_quota_offset)

				#create api key
				key_creation_response = AWS.APIGateway.Key.Create(apig,api_config.key_name,api_config.key_purpose)

				#add created key to usage plan
				key_added_response = AWS.APIGateway.UsagePlan.Add_Key(apig,usageplan_response['id'],key_creation_response['id'])

				#create api resource
				resource_creation_response = AWS.APIGateway.Resource.Create(apig,api_config.api_name,api_config.resource_name)
				
				#create method in resource for function
				method_creation_response = AWS.APIGateway.Method.Create(apig,api_config.api_name,api_config.resource_name,\
					api_config.http_method)

				#add integration
				#TODO: havent been able to totally use below code
				integration_added_response = AWS.APIGateway.Method.Add_Integration(apig,api_config.api_name,\
					resource_creation_response['id'],api_config.http_method,function_arn,integration_type='AWS')
			
				#create a deployment for the api
				deploy_resp = AWS.APIGateway.Deploy(apig,api_creation_response['id'],api_config.stage_name,\
					api_config.stage_purpose,api_config.deployment_purpose)

				#create stage for api
				create_stage_response = AWS.APIGateway.Create_Stage(apig,api_creation_response['id'],deploy_resp['id'],\
					api_config.stage_name,api_config.stage_purpose)

				#add stage to usage plan so uses api key
				usage_update_resp = AWS.APIGateway.UsagePlan.Add_Stage(apig,usageplan_response['id'],\
					api_creation_response['id'],api_config.stage_name)

				#create the source arn of this api method
				source_arn = 'arn:aws:execute-api:' + creds['region'] + \
					':' + integration_added_response['uri'].split(':')[9] + ':' + \
					api_creation_response['id'] + '/' + api_config.stage_name + '/' + '*'#api_config.http_method
					#'/' + api_config.resource_name + '/*'# + func_name

				#add permission to lambda for the stage's method
				resp = AWS.Lambda(creds).Add_Permission(fcn_name,source_arn)
				
				#the api endpoint url
				endpoint_url = 'https://' + api_creation_response['id'] + '.execute-api.' + creds['region'] + \
					'.amazonaws.com/' + api_config.stage_name + '/' + api_config.resource_name
				
				api_creation_response['x-api-key'] = key_creation_response['value']
				api_creation_response['Endpoint'] = endpoint_url

				return api_creation_response

			def serverless_check_package_size(dependancy_zip_filePath: str,cloudCreds_database: dict):
				#TODO: use serverless_usage to get sizes allowed, and then see how big potential function upload is
				return True

	class Cluster:
		"""For utilizing cloud virtual computing resources in the form of homogenous cluster.
		
		"""
		default_service_provider = 'digitalocean'

		#https://www.ovh.com/world/vps/vps-ssd.xml
		#gcloud, aws ec2, linode, ovh, vultr, rackspace, ...?

		#TODO: Assign instance schedules with tags
		#https://blog.cloudability.com/saved-64-devtest-instances-scheduling-uptime/

		def Deploy(cluster_config: ClusterConfig,creds='',package_filepath=None):
			"""Deploy a computing cluster.
			Args:
				cluster_config (ClusterConfig): Configuration for deploying a cluster.
				creds (dict): Credentials for the service.
				package_filepath (str): Default None, if provided can use an already packaged .zip of code to avoid recompilitation.
			Returns:
				ComputeCluster: compute_cluster
				str: dependancy_zip_filePath
			Notes:
				The process is as follows:
				1) Create docker container of python image.
				2) Pip install requirements inside environment inside container
				3) Extract environment by zip file out of container.
				4) Add in supplimentary files to zip.
				5) Spin up docker droplets, for each
				6) Create container of python image, extract dependancy zip inside
				7) Run compute_task command in container
			"""

			CloudManager.Cluster.Utils.NodeCountLimit(cluster_config.n_nodes) #check if adding new nodes is bad

			#start building the cluster
			compute_cluster = ComputeCluster({
				'cluster_config': cluster_config.Dictify(),
				'ip_addresses': [],
				'hardened_nodes': [],
				'createdDNs': []
				})

			#create list of setup commands
			setup_commands = CloudManager.Cluster.Security.Create_setup_commands(cluster_config.runtime,cluster_config.pip_requirements_list)

			#generate node names
			names = CloudManager.Cluster.Utils.Create_node_names(cluster_config.n_nodes,cluster_config.tag)

			#check if nodes already exist
			digo = DigitalOcean(creds)
			some_nodes_already_exist = any(DigitalOcean.Droplet.Exists(digo,names))
			if some_nodes_already_exist: raise ValueError('some of these nodes already exist - use AddNode')

			#create droplets
			print(str(datetime.now()) +' -- Creating droplets...')
			key, droplets = DigitalOcean.Droplet.CreateMultiple(digo,names,cluster_config.tag,cluster_config.asymKeys['public'],\
				useMonitoring=cluster_config.useMonitoring,
				image=cluster_config.OSimage,
				price=cluster_config.price_per_node,
				autoBackups=False,ipv6=False)
			print(str(datetime.now()) +' -- Droplets created...')

			#package the server deployment environment using a docker image
			print(str(datetime.now()) +' -- Creating dependancy package...')
			if package_filepath == None:
				dependancy_zip_filePath = CloudManager.Cluster.Transfer.CreateDependancyPackage(cluster_config.pip_requirements_list,cluster_config.sup_Filepaths_list)
			else:
				dependancy_zip_filePath = package_filepath

			#wait until droplets are active
			print(str(datetime.now()) +' -- Waiting for droplets to initialize...')
			compute_cluster = CloudManager.Cluster.Utils.WaitForNodes(compute_cluster,droplets)

			#get droplet ids
			droplet_ids = []
			for node in droplets:
				droplet_ids.append(node.id)

			#create firewalls
			print(str(datetime.now()) +' -- Creating cluster firewall...')
			CloudManager.Cluster.Security.SetFirewall(digo,cluster_config,droplet_ids)

			print(str(datetime.now()) +' -- Brief pause to ensure firewall/nodes completely activated.')
			time.sleep(30) #why wait so long?

			print(str(datetime.now()) +' -- Beginning droplet communication...')
			for node in range(0,cluster_config.n_nodes):
				print(str(datetime.now()) +' -- with node ' + str(node) + '...')

				#ssh connection to node as root
				com = Communication({'asymKeys':cluster_config.asymKeys,'ip_address':compute_cluster.ip_addresses[node],\
					'username':'root'}).Connect(port=22,timeout=600)

				#flash the dependancies onto the node into the container via ssh/sftp tunnel
				CloudManager.Cluster.Transfer.FlashPackage(com,dependancy_zip_filePath,setup_commands)

				#add hardened_node to compute_cluster
				#issues using non root with the docker install
				compute_cluster.hardened_nodes.append(CloudManager.Cluster.Security.Harden(com,admin_user='root',rsa_kb=8).Dictify())
				
				#close communication to this node
				com.Close()

			return compute_cluster,dependancy_zip_filePath

		def SendCommand(compute_cluster: ComputeCluster,command: str,node_idz=[],waitForResponse=True,timeout=10):
			"""Send a command to specified nodes in a cluster.
			Args:
				compute_cluster (ComputeCluster): Compute cluster to communicate with.
				command (str): Command to send to nodes.
				node_idz (list):  List of node indices to send command to.
				waitForResponse (bool): False to send and forget. 
				timeout (int): Seconds (if waiting for response) before closing connection.
			"""

			for node in node_idz:
				
				#TODO: dont use root user
				com = Communication({
					'asymKeys':compute_cluster.hardened_nodes[node]['asymKeys'],
					'ip_address':compute_cluster.hardened_nodes[node]['ip_address'],
					'username':compute_cluster.hardened_nodes[node]['username']
					}).Connect(port=compute_cluster.hardened_nodes[node]['ssh_port'],timeout=timeout)
				print(str(datetime.now())+ ' [' + compute_cluster.ip_addresses[node] + '] -> ' + command)
				#TODO: should add sudo here

				out,err = com.ExecuteCommand(command,waitForResponse=waitForResponse)
				for line in out:
					print (': ' + line)
				#time.sleep(10)
				com.Close()
			pass

		def PutSupFile(compute_cluster: ComputeCluster,sup_filepath: str,node_idz=[]):
			"""Put a supplimentary file into the operation environment within nodes in a cluster.
			Args:
				compute_cluster (ComputeCluster): Compute cluster to communicate with.
				sup_filePath (str): Local filepath of supplimentary file.
				node_idz (list): List of node indices to send file to.
			"""

			package = os.path.basename(sup_filepath)

			for node in node_idz:
				print(str(datetime.now())+ ' [' + compute_cluster.ip_addresses[node] + '] -> ' + package)
				com = Communication({
					'asymKeys':compute_cluster.hardened_nodes[node]['asymKeys'],
					'ip_address':compute_cluster.hardened_nodes[node]['ip_address'],
					'username':compute_cluster.hardened_nodes[node]['username']
					}).Connect(port=compute_cluster.hardened_nodes[node]['ssh_port'],timeout=600)

				out,err = com.ExecuteCommand(Docker.API.List())
				container_id = out[1].split()[0]

				#copy file to node
				x = 1
				while True:
					try:
						com.PutFile(sup_filepath,package)
						break
					except Exception as ex:
						print(str(datetime.now())+ ' !! Waiting ' + str(x) + '(s) to retry sending file.')
						time.sleep(x)
						x = x + 1
				time.sleep(5)
				#copy the file into the o_env inside container
				out,err = com.ExecuteCommand(Docker.API.CopyFile(\
					container_id,package,'/'+ Docker.operation_environment)) #copy tmp folder into container op env
				for line in out:
					print (': ' + line)
					
				time.sleep(5)
				com.Close()
			pass

		def AddNode(compute_cluster: ComputeCluster,creds=None,dependancy_zip_filePath=None):
			"""Add an additional node to a compute cluster.
			Args:
				compute_cluster (ComputeCluster): Compute cluster to communicate with.
				creds (dict): Credentials for the service.
				dependancy_zip_filePath (str): Local filepath of dependancy zip package to flash onto node.
			Returns:
				ComputeCluster: updated_compute_cluster
			"""
			if dependancy_zip_filePath == None:
				raise ValueError('Must specify dependancy package filepath')
			cluster_config = ClusterConfig(compute_cluster.cluster_config)

			CloudManager.Cluster.Utils.NodeCountLimit(cluster_config.n_nodes + 1) #check if adding new node is bad

			#create list of setup commands
			setup_commands = CloudManager.Cluster.Security.Create_setup_commands(\
				cluster_config.runtime,cluster_config.pip_requirements_list)

			#generate node names
			names = CloudManager.Cluster.Utils.Create_node_names(cluster_config.n_nodes+1,cluster_config.tag)

			#check if nodes already exist
			digo = DigitalOcean(creds)
			some_nodes_already_exist = any(DigitalOcean.Droplet.Exists(digo,names))
			if not some_nodes_already_exist: raise ValueError('this cluster doesnt exist?')

			#create droplets
			print(str(datetime.now()) +' -- Creating droplet...')
			key, droplet = DigitalOcean.Droplet.Create(digo,\
				names[-1],\
				cluster_config.tag,\
				cluster_config.asymKeys['public'],\
				useMonitoring=cluster_config.useMonitoring,
				image=cluster_config.OSimage,
				price=cluster_config.price_per_node,
				autoBackups=False,
				ipv6=False)

			#wait until droplets are active
			print(str(datetime.now()) +' -- Waiting for droplets to initialize...')
			x = 1
			while droplet.load().status != 'active':
				time.sleep(x)
				x = x + 1
			compute_cluster.ip_addresses.append(droplet.load().ip_address)

			#get droplet ids
			#droplet_ids = [droplet.id]
			#create firewalls
			#DigitalOcean.Security.AddDropletToFireWall(digo,droplet_ids)			#no need, goes by tag

			#ssh connection to node
			print(str(datetime.now()) +' -- Beginning droplet communication...')
			time.sleep(30)
			com = Communication({
				'asymKeys':cluster_config.asymKeys,
				'ip_address':compute_cluster.ip_addresses[-1],
				'username':'root'}).Connect(port=22,timeout=600)

			#flash the dependancies onto the node into the container via ssh/sftp tunnel
			CloudManager.Cluster.Transfer.FlashPackage(com,dependancy_zip_filePath,setup_commands)

			#add hardened_node to compute_cluster
			#issues using non root with the docker install
			compute_cluster.hardened_nodes.append(CloudManager.Cluster.Security.Harden(com,admin_user='root',rsa_kb=8).Dictify())

			#close ssh com
			com.Close()

			#adjust the compute cluster
			compute_cluster.cluster_config['n_nodes'] = compute_cluster.cluster_config['n_nodes'] + 1

			return compute_cluster

		def RebootNodes(compute_cluster: ComputeCluster,node_idz=[]):
			"""INCOMPLETE.
			"""
			raise ValueError('why reboot node when can jsut reboot container')
			CloudManager.Cluster.SendCommand(compute_cluster,\
				'reboot',
				node_idz=node_idz,
				#waitForResponse=False,\
				)
			CloudManager.Cluster.SendCommand(compute_cluster,\
				Docker.API.Start(),
				node_idz=node_idz,
				#waitForResponse=False,\
				)

			pass

		def RebootContainer(compute_cluster: ComputeCluster,node_idz=[]):
			"""Stop and restart the running container on nodes in a cluster.
			Args:
				compute_cluster (ComputeCluster): Compute cluster to communicate with.
				node_idz (list): List of node indices to send container reboot to.
			"""

			#send stop command to container
			CloudManager.Cluster.SendCommand(compute_cluster,Docker.API.Stop(),node_idz=node_idz)

			#send start command to container
			CloudManager.Cluster.SendCommand(compute_cluster,Docker.API.Start(),node_idz=node_idz)

			pass

		def Shutdown(clustertag:str,nodes=[]):
			"""INCOMPLETE"""
			pass

		def PowerOn():
			"""INCOMPLETE"""
			pass

		class Security:
			"""For managing security with a Cluster.
			"""

			def SetFirewall(digo: DigitalOcean,cluster_config: ClusterConfig,droplet_ids: list):
				"""Set a firewall around a cluster.
				Args:
					digo (DigitalOCean): 
					cluster_config (ClusterConfig):
					droplet_ids (list):
				Notes:
					If firewall is already up, does nothing.
					"""
				#create firewalls
				ssh_inbound_rule = DigitalOcean.Security.FirewallRule.ssh_inbound_rule()
				outbound_rules = []
				#if cluster_config.useMonitoring:
				#	outbound_rules.append(DigitalOcean.Security.FirewallRule.monitoringauth_outbound_rule())
				#	outbound_rules.append(DigitalOcean.Security.FirewallRule.monitoringmetrics_outbound_rule())
				#outbound_rules.append(DigitalOcean.Security.FirewallRule.docker_outbound_rule())
		
				outbound_rules.append(DigitalOcean.Security.FirewallRule.all_tcp_outbound_rule())
				outbound_rules.append(DigitalOcean.Security.FirewallRule.all_udp_outbound_rule())

				#apply firewall
				try:
					firewall = DigitalOcean.Security.Create_Firewall(digo,cluster_config.tag + '-fw',droplet_ids,cluster_config.tag,\
						[ssh_inbound_rule],outbound_rules)
				except Exception as ex:
					a = 5 #lready exists - confirm rules? OR FAILED - does this add new droplets to it?

				pass

			def Create_setup_commands(runtime: str,pip_requirements_list: list):
				"""Create list of setup commands for deploying a cluster.
				Args:
					runtime (str): Container runtime designation.
					pip_requirements_list (list): list of pip requirements from retuirements.txt.
				Returns:
					list: setup_commands
				"""
				setup_commands = []
				setup_commands.append(Docker.API.Create(image=Docker.image_for_runtime[runtime]))
				setup_commands.append(Docker.API.Start())
				setup_commands.append(Docker.API.ArbitraryCommand(command=Linux.API.MakeDir(Docker.operation_environment)))
				#TODO: dont need this on cloud nodes? until the pip installing is done on them
				#setup_commands.append(Docker.API.ArbitraryCommand(command='yum install -y git')) #for when need to use pip3 to get githubs
				#yum versus apt-get because amazon ami
				#setup_commands.append(Docker.API.ArbitraryCommand(command='pip install --upgrade pip'))

				#this is handled in containers Docker.Create
				#for pkg in pip_requirements_list:
					#setup_commands.append(Docker.API.PipInstall(pkg,'/' + Docker.operation_environment + '/'))

				#make swap file to help with OOM
				#https://gist.github.com/cobyism/58f5463869aaf84184f0
				#https://www.digitalocean.com/community/tutorials/how-to-add-swap-space-on-ubuntu-16-04
				setup_commands.append(Linux.API.Performance.CreateSwapfile(size_gb=4))
				setup_commands.append(Linux.API.Performance.LockSwapfile())
				setup_commands.append(Linux.API.Performance.MarkSwapfile())
				setup_commands.append(Linux.API.Performance.EnableSwapfile())
				setup_commands.append(Linux.API.Performance.PermanentizeSwapfile())
				setup_commands.append(Linux.API.Performance.SetSwappiness(swappiness=20))
				setup_commands.append(Linux.API.Performance.SetCachePressure(pressure=50))

				#TODO: make /etc a git itself
				#https://help.ubuntu.com/lts/serverguide/etckeeper.html.en

				return setup_commands

			def MakeSudoAdmin(com: Communication,admin_user: str,rsa_kb: int):
				"""Add an admin user with sudo privlidges.
				Args:
					com (Communication):
					admin_user (str):
				Returns:
					dict: asymKeys
				Ref:
					https://www.digitalocean.com/community/questions/how-to-log-in-as-non-root-user-via-ssh
					https://www.digitalocean.com/community/questions/secure-ubuntu-server-for-non-root-user-using-only-ssh-keys?answer=22286
				"""
				#add an admin user instead of root
				out,err = com.ExecuteCommand(Linux.API.Security.AddUser(admin_user),waitForResponse=False)
				out,err=com.ExecuteCommand(Linux.API.Security.AddUserToGroup(admin_user,group='sudo'))
				out,err=com.ExecuteCommand(Linux.API.MakeDir('/home/' + admin_user + '/.ssh',parents=True)) #make dir
				out,err=com.ExecuteCommand('touch /home/' + admin_user + '/.ssh/authorized_keys') #make authorized ssh keys file
				out,err=com.ExecuteCommand('chown ' + admin_user + ':' + admin_user + ' /home/' + admin_user + '/.ssh')
				out,err=com.ExecuteCommand('chown ' + admin_user + ':' + admin_user + ' /home/' + admin_user + '/.ssh/authorized_keys')
				out,err=com.ExecuteCommand('chmod 700 /home/' + admin_user + '/.ssh')

				#prevent others from messing with file? https://help.ubuntu.com/lts/serverguide/openssh-server.html.en
				#chmod 600 .ssh/authorized_keys
				out,err=com.ExecuteCommand('chmod 600 /home/' + admin_user + '/.ssh/authorized_keys')
				
				#make it so dont need password and can assume sudo
				#https://stackoverflow.com/questions/21659637/how-to-fix-sudo-no-tty-present-and-no-askpass-program-specified-error
				#https://stackoverflow.com/questions/323957/how-do-i-edit-etc-sudoers-from-a-script
				out,err=com.ExecuteCommand('echo "' + admin_user + ' ALL=(ALL) NOPASSWD: ALL" | (EDITOR="tee -a" visudo)')

				#generate new rsa key for this admin user ssh
				asymKeys = Encrypting.Asymmetric.GenerateKey('asym key',rsa_kb,'OpenSSH')
				public_key = asymKeys['public']
				rsa_lines = public_key.split('\n')

				#upload key
				out,err = com.ExecuteCommand(Linux.API.WriteFile(rsa_lines,'/home/' + admin_user + '/.ssh/authorized_keys'),waitForResponse=True)

				#TODO: also get rid of all other keys?
				#what about changing the algos to pass an audit?

				return asymKeys

			def ChangeRootKey(com: Communication,rsa_kb: int):
				"""Change the SSH keey for the root user.
				Args:
				
				
				"""
				#generate new rsa key for this admin user ssh
				asymKeys = Encrypting.Asymmetric.GenerateKey('asym key',rsa_kb,'OpenSSH')
				public_key = asymKeys['public']
				rsa_lines = public_key.split('\n')

				#upload key
				out,err = com.ExecuteCommand(Linux.API.WriteFile(rsa_lines,'~/.ssh/authorized_keys'),waitForResponse=True)

				#TODO: also get rid of all other keys?
				#what about changing the algos to pass an audit?

				return asymKeys

			def Configure_SSH(com: Communication,username: str,new_ssh_port: int):
				"""Configure the SSH daemon to a hardened state.
				Args:
					com (Communcation):
					username (str):
					new_ssh_port (int):
				"""
				#extract the ssh daemon config file
				sshd_config_lines,err = com.ExecuteCommand(Linux.API.ReadFile('/etc/ssh/sshd_config'),waitForResponse=True)

				#rewrite with hardened config settings
				out,err = com.ExecuteCommand(Linux.API.WriteFile(\
					Linux.API.Security.SSH_Harden(username,sshd_config_lines,new_ssh_port),\
					'/etc/ssh/sshd_config',addNewLine=False),waitForResponse=True)

				#TODO: if restart now, will lock out root?
				#https://www.digitalocean.com/community/questions/how-can-i-disable-ssh-login-for-a-root-user-i-am-the-account-owner
				out,err = com.ExecuteCommand('/etc/init.d/ssh restart',waitForResponse=True)


				#/etc/init.d/ssh restart #command to restart ssh https://github.com/besnik/tutorials/tree/master/linux-hardening
				#sudo systemctl restart sshd https://www.linode.com/docs/security/securing-your-server/
				#sudo systemctl restart sshd.service https://help.ubuntu.com/lts/serverguide/openssh-server.html.en
				#sudo systemctl reload sshd https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
				#sshd -t #tests if valid? https://medium.com/@jasonrigden/hardening-ssh-1bcb99cd4cef
				
				out,err = com.ExecuteCommand(Linux.API.ReadFile('/etc/ssh/sshd_config'),waitForResponse=True)

				pass

			def SetNodewall(com: Communication,new_ssh_port: int):
				"""Install and configure Uncomplicated FireWall to give node its own firewall.
				Args:
				
				Ref:
					https://www.digitalocean.com/community/tutorials/how-to-setup-a-firewall-with-ufw-on-an-ubuntu-and-debian-cloud-server
				"""
				out,err = com.ExecuteCommand(Linux.API.Install('ufw'),waitForResponse=True)
				out,err = com.ExecuteCommand(Linux.API.Security.BlockAllInBut(new_ssh_port),waitForResponse=True)
				out,err = com.ExecuteCommand('ufw enable',waitForResponse=False)
				time.sleep(10)
				pass

			def SetFail2Ban(com: Communication,new_ssh_port: int):
				"""Install and configure fail2ban to jail failed connecting agents.
				Args:
					com (Communication):
					new_ssht_port (int):
				"""
				#https://kyup.com/tutorials/protect-ssh-fail2ban/
				#install fail2ban
				out,err = com.ExecuteCommand(Linux.API.Install('fail2ban -y'),waitForResponse=True)
				
				#copy the jail config
				#cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
				#https://www.linode.com/docs/security/using-fail2ban-for-security/
				#https://github.com/fail2ban/fail2ban/issues/1986
				#https://www.booleanworld.com/protecting-ssh-fail2ban/
				#https://www.digitalocean.com/community/tutorials/how-fail2ban-works-to-protect-services-on-a-linux-server
				ssh_jail = Linux.API.Security.Generate_ssh_jail(new_ssh_port)
				out,err = com.ExecuteCommand(Linux.API.WriteFile(ssh_jail,'/etc/fail2ban/jail.local'),waitForResponse=True)
				
				#start fail2ban
				#https://www.linode.com/docs/security/securing-your-server/
				out,err = com.ExecuteCommand('/etc/init.d/fail2ban restart',waitForResponse=True)
				pass

			def DisableSharedMemExecution(com: Communication):
				"""Lock down shared memory by removing permission to execute programs.
				Args:
					com (Communication):
				Ref:
					https://www.techrepublic.com/article/how-to-enable-secure-shared-memory-on-ubuntu-server/
					https://help.ubuntu.com/community/StricterDefaults
				"""
				#https://help.ubuntu.com/community/StricterDefaults
				#none /run/shm tmpfs defaults,ro 0 0

				#none /run/shm tmpfs rw,noexec,nosuid,nodev 0 0
				out,err = com.ExecuteCommand(Linux.API.ReadFile('/etc/fstab'),waitForResponse=True)
				for line in out:
					if 'none /run/shm tmpfs rw,noexec,nosuid,nodev 0 0' in line:
						return
				out.append('none /run/shm tmpfs rw,noexec,nosuid,nodev 0 0')
				out,err = com.ExecuteCommand(Linux.API.WriteFile(out,'/etc/fstab',addNewLine=False),waitForResponse=True)

				pass

			def ConfigureNetworkVariables(com: Communication):
				"""Configure network variables to prevent simple attacks.
				Args:
					com (Communication):
				"""
				out,err = com.ExecuteCommand(Linux.API.ReadFile('/etc/sysctl.conf'),waitForResponse=True)

				out,err = com.ExecuteCommand(Linux.API.WriteFile(\
					Linux.API.Security.Harden_sysctl(out),\
					'/etc/sysctl.conf',addNewLine=False),waitForResponse=True)

				pass

			def Harden(com: Communication,admin_user='default_admin_user',rsa_kb=4):
				"""Harden a compute node.
				Args:
					com (Communication):
					##new_ssh_port (int):
					rsa_kb (int): KB size of RSA key for SSH
				Returns:
					HardenedNode: hardened_node
				Ref:
					https://www.linode.com/docs/security/securing-your-server/
				"""
				
				new_ssh_port = 22 #dont want to have to deal with managing multiple ports

				#make an admin user sudo, can ssh using asymKeys generated
				print(str(datetime.now()) +' -- Creating sudo admin user')
				#asymKeys = CloudManager.Cluster.Security.MakeSudoAdmin(com,admin_user,rsa_kb)
				asymKeys = CloudManager.Cluster.Security.ChangeRootKey(com,rsa_kb)

				#configure network variables
				print(str(datetime.now()) +' -- Configuring network vars')
				CloudManager.Cluster.Security.ConfigureNetworkVariables(com)
				
				#set firewall on node
				print(str(datetime.now()) +' -- Configuring node firewall')
				CloudManager.Cluster.Security.SetNodewall(com,new_ssh_port)
				
				#set fail2ban
				print(str(datetime.now()) +' -- Configuring fail2ban')
				CloudManager.Cluster.Security.SetFail2Ban(com,new_ssh_port)

				#lockdown shared memory
				print(str(datetime.now()) +' -- Disabling shared memory space')
				CloudManager.Cluster.Security.DisableSharedMemExecution(com)

				#configure the ssh daemon
				print(str(datetime.now()) +' -- Configuring ssh daemon')
				CloudManager.Cluster.Security.Configure_SSH(com,admin_user,new_ssh_port)

				#mac address
				out,err=com.ExecuteCommand(Linux.API.Net.MAC_address(),waitForResponse=True)

				hardened_node = HardenedNode({
					'username': admin_user,
					'ssh_port': new_ssh_port,
					'asymKeys': asymKeys,
					'mac_address': out[0][:-1],
					'ip_address': com.ip_address
					})

				return hardened_node

			def ReadLogs():

				#/var/log/auth.log for fail2ban ssh jail
				#fail2ban-client status
				#https://hostpresto.com/community/tutorials/how-to-secure-your-ssh-using-fail2ban/
				#iptables -S
				#https://www.a2hosting.com/kb/security/hardening-a-server-with-fail2ban

				pass

		class Transfer:
			"""For transferring code onto a Cluster.
			"""

			def FlashPackage(com: Communication,dependancy_zip_filePath: str,setup_commands: list):
				"""Flash a dependancy package onto a node and into it's container through ssh and sftp.
				Args:
					com (Communication):
					dependancy_zip_filePath (str):
					setup_commands (list):
				"""
				#setup the node virtual environment
				container_id = CloudManager.Cluster.Transfer.SetUpNode(com,setup_commands)

				#transfer the depenancies in a package
				package = CloudManager.Cluster.Transfer.SendPackage(com,dependancy_zip_filePath)

				#extract environment from package into container and remove temp
				CloudManager.Cluster.Transfer.CleanUpDeploymentPackage(com,package,container_id)

				pass

			def SendPackage(com :Communication,dependancy_zip_filePath: str):
				"""Send a dependancy zipfile as a package to a node.
				Args:
					com (Communication):
					dependancy_zip_filePath (str):
				Returns:
					str: package
				TODO: allow for dependancy_zip_filePath to be a cloud file so only need to upload once, and nodes download from cloud 
				"""
				print(str(datetime.now()) +' -- Transferring deployment package to node...')
				package = os.path.basename(dependancy_zip_filePath)
				x = 1
				while True:
					try:
						com.PutFile(dependancy_zip_filePath,package)
						break
					except Exception as ex:
						time.sleep(x)
						x = x + 1

				return package

			def CleanUpDeploymentPackage(com: Communication,package: str,container_id: str):
				"""Clean up a node by removing temporary files/folders for installing a deployment package.
				Args:
					com (Communication):
					pacakge (str):
					container_id (str):
				"""
				print(str(datetime.now()) +' -- Extracting package into container...')
				
				out,err = com.ExecuteCommand(Linux.API.Install('unzip')) #need unzip package
				for line in out:
					print (': ' + line)
				
				out,err = com.ExecuteCommand(Linux.API.MakeDir('pkgtmp')) #make the tmp dir
				for line in out:
					print (': ' + line)
				
				out,err = com.ExecuteCommand(Linux.API.Unzip(package,'pkgtmp')) #unzip into tmp dir
				
				out,err = com.ExecuteCommand(Docker.API.CopyFile(\
					container_id,'pkgtmp/.','/'+ Docker.operation_environment)) #copy tmp folder into container op env
				for line in out:
					print (': ' + line)
				
				out,err = com.ExecuteCommand(Linux.API.DeleteDir('pkgtmp')) #delete the tmp dir
				for line in out:
					print (': ' + line)
				
				out,err = com.ExecuteCommand(Linux.API.DeleteDir(package)) #delete the package
				for line in out:
					print (': ' + line)

				pass

			def CreateDependancyPackage(pip_requirements_list: list,sup_Filepaths_list: list):
				"""Create a dependancy package to send to a node.
				Args:
					pip_requirements_list (list):
					sup_Filepaths_list (list):
				Returns:
					dependancy_zip_filePath (str):
				"""

				#TODO: MOVE package the server deployment environment using a docker image HERE TO INCREASE SPEED

				#package the server deployment environment using a docker image
				print(str(datetime.now()) +' -- Creating package...')

				dependancy_zip_filePath = Docker.Compile(
					Docker.operation_environment,
					AWS.Lambda.image,
					pip_requirements_list=pip_requirements_list)

				#add the function file into the dependancy zip
				zip = zipfile.ZipFile(dependancy_zip_filePath,'a')
				#add supplimentary files
				if len(sup_Filepaths_list) > 0:
					for sup_Filepath in sup_Filepaths_list:
						zip.write(sup_Filepath, os.path.basename(sup_Filepath))
				zip.close()

				return dependancy_zip_filePath

			def SetUpNode(com: Communication,setup_commands: list):
				"""Setup a node by executing setup commands on it.
				Args:
					com (Communication): 
					setup_commands (list):
				Returns:
					container_id (str):
				"""
				print(str(datetime.now()) +' -- Executing container setup commands...')
				for c in range(len(setup_commands)):
					command = setup_commands[c]
					print(str(datetime.now()) +' (' + str(c) + '/' + str(len(setup_commands))  + ') -> ' + command)
					x = 1
					while True:
						try:
							out,err = com.ExecuteCommand(command)
							for line in out:
								print (': ' + line)
							break
						except Exception as ex:
							time.sleep(x)
							x = x + 1

				#capture container id
				out,err = com.ExecuteCommand(Docker.API.List())
				container_id = out[1].split()[0]
				return container_id

		class Economics:
			"""For managing the economics of a Cluster.
			"""

			def RunningCost(compute_cluster: ComputeCluster,creds=''):
				"""Compute the running cost of a ComputeCluster.
				Args:
					compute_cluster (ComputeCluster):
					creds (dict):
				Returns:
					cost (float):
					startedDNs (list):
					elapseds (list):
					"""
				
				startedDNs = []
				elapseds = []

				#get all the droplets 
				droplets = DigitalOcean.Droplet.ListAll(DigitalOcean(creds))

				def dt2num(dt):
					return (dt - dt.min).total_seconds()

				nowDN = dt2num(datetime.utcnow())
				for node in droplets:
					if node.ip_address in compute_cluster.ip_addresses:
						startedDNs.append(dt2num(datetime.strptime(node.created_at[:-1],'%Y-%m-%dT%H:%M:%S')))
						elapseds.append(nowDN-startedDNs[-1])
				
				#seconds -> minutes -> hours -> mos -> cost_per_mo
				cost = sum(elapseds)/60/60/720*compute_cluster.cluster_config['price_per_node']
				running_costs = {
					'dollars': cost,
					'total_hours_elapsed': sum(elapseds)/60/60,
					'started_datenums': startedDNs,
					'elapseds': elapseds,
					}
				return running_costs

		class Utils:

			def NodeCountLimit(n_nodes_total: int):
				"""Checks the limit of nodes.
				Raises:
					ValueError: Cant do cluster larger than 10 currently."""
				if n_nodes_total > 10:
					#https://www.digitalocean.com/docs/networking/firewalls/overview/
					raise ValueError('Cant do cluster larger than 10 currently.')

				pass

			def Create_node_names(n_nodes: int,tag: str):
				"""Create name for each node.
				Args:
					n_nodes (int): Number of nodes.
					tag (str): The cluster's tag.
				Returns:
					list: names"""
				names = []
				for node in range(0,n_nodes):
					names.append('node-' + str(node) + '-' + tag)
				return names

			def WaitForNodes(compute_cluster: ComputeCluster,droplets: list):
				"""Waits for droplets to finish initializing and records their creation time and ip address to the cluster.
				Args:
					compute_cluster (ComputeCluster):
					droplets (list):
				Returns:
					ComputeCluster: compute_cluster
				"""
				print(str(datetime.now()) +' -- Waiting on droplets...')
				node = 0
				for node in range(0,compute_cluster.cluster_config['n_nodes']):
					x = 1
					while droplets[node].load().status != 'active':
						time.sleep(x)
						x = x + 1
					compute_cluster.ip_addresses.append(droplets[node].load().ip_address)

				return compute_cluster

	class Stats:

		#TODO: costs? storage? all usages/capacities

		def serverless_usage(cloudCreds_database: dict):

			lambda_summary = AWS.Lambda(cloudCreds_database).Summary()
			lambda_summary['AccountUsage']['CodeCapacity'] = lambda_summary['AccountUsage']['TotalCodeSize']/lambda_summary['AccountLimit']['TotalCodeSize']

			return lambda_summary
		
	class IAM:
		"""For interacting with Identity Access Management services.
		Ref:
			https://docs.aws.amazon.com/IAM/latest/UserGuide/id.html
		"""
		service = 'aws' #'wasabi

		service_router = {
			'aws': lambda creds: AWS.IAM(creds),
			'wasabi': lambda creds: Wasabi(creds,resource='iam'),
			}

		def Summary(max_items=100,creds=''):
			"""Summary of IAM.
			Args:
				max_items (int):
				creds (dict): Credentials for the service.
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			summary = AWS.IAM.Summary(iam,maxitems=max_items)

			return summary

		def List_Users(tag='/',max_items=100,creds=''):
			"""List the Users.
			Args:
				tag (str):
				max_items (int):
				creds (dict): Credentials for the service.
			Returns:
				list: user_dicts
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			user_dicts = AWS.IAM.User.List(iam,tag=tag,maxitems=max_items)['Users']

			return user_dicts

		def List_Groups(tag='/',max_items=100,creds=''):
			"""List all IAM groups.
			Args:
				tag (str): Custom tag to help group/identify.
				max_items (int):
				creds (dict): Credentials for the service.
			Returns:
				list: groups
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			groups = AWS.IAM.Group.List(iam,maxitems=max_items)['Groups']

			return groups

		def List_Roles(tag='/',max_items=100,creds=''):
			"""List the Roles.
			Args:
				tag (str): Custom tag to help group/identify.
				max_items (int):
				creds (dict): Credentials for the service.
			Returns:
				list: roles
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			roles = AWS.IAM.Role.List(iam,maxitems=max_items)['Roles']

			return roles

		def List_Policies(tag='/',max_items=100,creds=''):
			"""List the Policies
			Args:
				tag (str):
				max_items (int):
				creds (dict): Credentials for the service.
			Returns:
				list: policies
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			policies = AWS.IAM.Policy.List(iam,maxitems=max_items)['Policies']

			return policies

		def Create_User(name: str,tag='/',creds=''):
			"""Create an IAM User.
			Args:
				name (str): Unique name of user.
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				iam.User: ??? aws boto3 obj?
			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			user_create_resp = AWS.IAM.User.Create(iam,name,tag=tag)

			return user_create_resp

		def Delete_User(name: str,creds=''):
			"""Delete an IAM User.
			Args:
				name (str): Unique name of user.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			resp = AWS.IAM.User.Delete(iam,name)

			return resp

		def List_User_accesskeys(name: str,creds=''):
			"""Delete an IAM User.
			Args:
				name (str): Unique name of user.
				creds (dict): Credentials for the service.
			Returns:
				list: access_keys
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			access_keys = AWS.IAM.User.List_AccessKeys(iam,name)

			return access_keys

		def Generate_User_accesskey(name: str,creds=''):
			"""Generate access key for user.
			Args:
				name (str): Unique name of user.
				creds (dict): Credentials for the service.
			Returns:
				dict: response
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.User.Generate_AccessKey(iam,name)

			return response

		def Update_User_accesskey(name: str,is_active: bool,creds=''):
			"""Change the active status for a user's access key
			Args:
				name (str): Unique name of user.
				is_active (bool): False to inactivate the key
				key_ind (int): Index of key to update when listed for user.
				creds (dict): Credentials for the service.
			Returns:
				dict: response
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)

			status = 'Active' if is_active else 'Inactive'

			response = AWS.IAM.User.Update_AccessKey(iam,name,status,key_ind=key_ind)

			return response

		def Delete_User_accesskey(name: str,key_ind=0,creds=''):
			"""Delete an access key for user.
			Args:
				name (str): Unique name of user.
				key_ind (int): Index of key to update when listed for user.
				creds (dict): Credentials for the service.
			Returns:
				dict: response
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.User.Delete_AccessKey(iam,name,key_ind=key_ind)

			return response

		def Show_User_accesskey_lastused(name: str,key_ind=0,creds=''):
			"""Show the last usage of an access key for user.
			Args:
				name (str): Unique name of user.
				key_ind (int): Index of key to update when listed for user.
				creds (dict): Credentials for the service.
			Returns:
				dict: response
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.User.AccessKey_LastUse(iam,name,key_ind=key_ind)

			return response

		def Create_Policy(name: str,purpose: str,statements: list,tag='/',creds=''):
			"""Creates an IAM Policy.
			Args:
				name (str): 'identifier' of the policy
				purpose (str): 'Meaningful description of the purpose of the policy'
				statements: list; [statement1,statement2,...]; use Statementize
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				dict: server_response
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Policy.Create(iam,name,purpose,statements,tag=tag)

			return response

		def Delete_Policy(name: str,tag='/',creds=''):
			"""Deletes an IAM Policy.
			Args:
				name (str): 'identifier' of the policy
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				bool: response_OK
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Policy.Delete(iam,name,tag=tag,scope='All')

			return response['ResponseMetadata']['HTTPStatusCode'] == 200

		def Create_Group(name: str,tag='/',creds=''):
			"""Createa an IAM group.
			Args:
				name (str):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				iam.Group: boto3 obj?
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.Create(iam,name,tag=tag)

			return response

		def Delete_Group(name: str,creds=''):
			"""Createa an IAM group.
			Args:
				name (str):
				creds (dict): Credentials for the service.
			Returns:
				bool: response_OK
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.Delete(iam,name)

			return response['ResponseMetadata']['HTTPStatusCode'] == 200

		def Add_User_to_Group(groupname: str,username: str,creds=''):
			"""Add an IAM User to an IAM Group.
			Args:
				groupname (str):
				username (str):
				creds (dict): Credentials for the service.
			Returns:
				bool: response_OK
			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.Add_User(iam,groupname,username)
			
			return response['ResponseMetadata']['HTTPStatusCode'] == 200

		def Remove_User_from_Group(groupname: str,username: str,creds=''):
			"""Remove an IAM User to an IAM Group.
			Args:
				groupname (str):
				username (str):
				creds (dict): Credentials for the service.
			Returns:
				bool: response_OK
			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.Remove_User(iam,groupname,username)
			
			return response['ResponseMetadata']['HTTPStatusCode'] == 200

		def List_Groups_Policies(name: str,creds=''):
			"""List all the policies attached to an IAM Group.
			Args:
				name (str):
				creds (dict): Credentials for the service.
			Returns:
				list: 
			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.List_Policies(iam,name)

			return response

		def List_Groups_Attached_Policies(name: str,tag='/',creds=''):
			"""List all the policies attached to an IAM Group.
			Args:
				name (str):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				list: 
			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.List_Attached_Policies(iam,name,tag=tag)

			return response

		def Attach_Group_Policy(groupname: str,policyname: str,tag='/',creds=''):
			"""Attach a policy to an IAM group.
			Args:
				groupname (str):
				policyname (str):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.Attach_Policy(iam,groupname,policyname,tag=tag)

			return response

		def Remove_Group_Policy(groupname: str,policyname: str,tag='/',creds=''):
			"""Attach a policy to an IAM group.
			Args:
				groupname (str):
				policyname (str):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:
				
			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Group.Remove_Policy(iam,groupname,policyname,tag=tag)

			return response

		def Create_Role(name: str,purpose: str,service: str,max_session_duration_s=3600,tag='/',creds=''):
			"""Create an IAM Role.
			Args:
				name (str):
				purpose (str):
				service (str):
				max_session_duration_s (int):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:

			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Role.Create(iam,name,purpose,service,tag=tag,max_session_duration_s=max_session_duration_s)

			return response

		def Delete_Role(name: str,creds=''):
			"""Delete an IAM Role.
			Args:
				name (str):
				creds (dict): Credentials for the service.
			Returns:

			"""

			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Role.Delete(iam,name)

			return response

		def Attach_Policy_to_Role(rolename: str,policyname: str,tag='/',creds=''):
			"""Attach a existing policy to a Role.
			Args:
				rolename (str):
				policyname (str):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:

			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Role.Attach_Policy(iam,rolename,policyname,tag=tag)

			return response

		def Remove_Policy_from_Role(rolename: str,policyname: str,tag='/',creds=''):
			"""Remove a policy from a Role.
			Args:
				rolename (str):
				policyname (str):
				tag (str): Custom tag to help group/identify.
				creds (dict): Credentials for the service.
			Returns:

			"""
			iam = CloudManager.IAM.service_router[CloudManager.IAM.service](creds)
			response = AWS.IAM.Role.Attach_Policy(iam,rolename,policyname,tag=tag)

			return response

		class Utils:

			def List_policy_actions():
				"""List all the policy actions available for the specified service.
				TODO:
					Currently incapable of being done?
					https://stackoverflow.com/questions/51930111/boto3-get-available-actions-per-service
				"""
				raise NotImplementedError()

			def Statementize(service: str,actions: list,effect: str,resources: list):
				"""For creating an IAM policy statement.
				Args:
					service (str): aws service id like 's3' or 'lambda' or 'dynamodb'
					action (list): list of strings -> ['PutObject','GetObject','*']
					effect (str): 'Allow'|'Deny'
					resources (list): list of resource strings -> ['mybucket1/*','mybucket2','*']
				Returns:
					dict: policy_statement
				"""

				return AWS.IAM.Policy.Statementize(service,actions,effect,resources)

class Tests:

	def upload_download_speeds(nKBytes=100,n_objs=100,creds=''):
		"""Test object storage uploading and downloading by measuring speeds and comparing mulithreaded batch functions.
		Notes:
			Data rates apply!
			"""
		test_bucketname = 'test_tablename-drive'
		test_objectname = 'obj1'
		test_objectnames = []
		for k in range(n_objs):
			test_objectnames.append(test_objectname + str(k))
		obj_as_str = '1'*nKBytes * 1024
		obj_bytesize = len(obj_as_str)

		CloudManager.ObjectStorage.CreateBucket(test_bucketname,creds=creds)

		t1 = time.time()
		res = CloudManager.ObjectStorage.Upload(obj_as_str,test_bucketname,test_objectname,creds=creds)
		t2 = time.time()
		res = CloudManager.ObjectStorage.BatchUpload([obj_as_str]*n_objs,[test_bucketname]*n_objs,test_objectnames,creds=creds)
		t3 = time.time()
		print('-- UPLOAD SPEEDS--')
		single_bytes_s = (obj_bytesize/(t2-t1))/1024
		threaded_bytes_s = ((obj_bytesize*n_objs)/(t3-t2))/1024
		print('single upload bytes/s = ' + str(single_bytes_s)[:-10] + ' KB/s')
		print('batch upload x' + str(n_objs) + ' bytes/s = ' + str(threaded_bytes_s)[:-10] + ' KB/s')

		t1 = time.time()
		res = CloudManager.ObjectStorage.Download(test_bucketname,test_objectname,creds=creds,decodeBytes=False)
		t2 = time.time()
		res = CloudManager.ObjectStorage.BatchDownload([test_bucketname]*n_objs,test_objectnames,creds=creds,decodeBytes=False)
		t3 = time.time()
		print('-- DOWNLOAD SPEEDS--')
		single_bytes_s = (obj_bytesize/(t2-t1))/1024
		threaded_bytes_s = ((obj_bytesize*n_objs)/(t3-t2))/1024
		print('single download bytes/s = ' + str(single_bytes_s)[:-10] + ' KB/s')
		print('batch download x' + str(n_objs) + ' bytes/s = ' + str(threaded_bytes_s)[:-10] + ' KB/s')

		pass

	def rename_exists_delete_speeds(n_objs=100,creds=''):
		"""Test object storage renaming, existing, and deleting by measuring speeds and comparing mulithreaded batch functions.
		Notes:
			Data rates apply!
			"""
		test_bucketname = 'test_tablename-drive'
		test_objectname = 'obj1'
		test_objectnames = []
		for k in range(n_objs):
			test_objectnames.append(test_objectname + str(k))
				
		new_names  = []
		for k in range(n_objs):
			new_names.append(test_objectnames[k] + '-')

		t1 = time.time()
		res = CloudManager.ObjectStorage.Rename(test_bucketname,test_objectname,test_objectname+'-',creds=creds)
		t2 = time.time()
		res = CloudManager.ObjectStorage.BatchRename([test_bucketname]*n_objs,test_objectnames,new_names,creds=creds)
		t3 = time.time()
		print('-- RENAME SPEEDS--')
		print('single rename = ' + str(t2-t1)[:-10] + 's')
		print('batch rename x' + str(n_objs) + ' = ' + str(t3-t2)[:-10] + ' s')

		t1 = time.time()
		res = CloudManager.ObjectStorage.Exists(test_bucketname,test_objectname+'-',creds=creds)
		t2 = time.time()
		res = CloudManager.ObjectStorage.BatchExists([test_bucketname]*n_objs,new_names,creds=creds)
		t3 = time.time()
		print('-- EXISTS SPEEDS--')
		print('single exist = ' + str(t2-t1)[:-10] + 's')
		print('batch exists x' + str(n_objs) + ' = ' + str(t3-t2)[:-10] + ' s')

		t1 = time.time()
		res = CloudManager.ObjectStorage.Delete(test_bucketname,test_bucketname+'-',creds=creds)
		t2 = time.time()
		res = CloudManager.ObjectStorage.BatchDelete(test_bucketname,new_names,creds=creds)
		t3 = time.time()
		print('-- DELETE SPEEDS--')
		print('single delete = ' + str(t2-t1)[:-10] + 's')
		print('batch delete x' + str(n_objs) + ' = ' + str(t3-t2)[:-10] + ' s')
		pass


readme = """
# Cloud

The Cloud package is designed to be a modular wrapper for interacting with typical cloud services such as AWS, DigitalOcean, and Wasabi. The idea behind this package is that as services change so can your usage simply by changing the credentials. Additionally, much of cloud service functionality requires locally building/compiling code and this package depends upon <strong>Docker</strong> for this (only tested on Windows PCs).


# Installation
Installing to use in your own scripts in a virtual environment?

`pip install git+https://github.com/pmp47/Cloud`

Installing to edit this code and contribute? Clone/download this repo and...

`pip install -r requirements.txt`

# Credentials

All of the cloud service providers impliment forms of authentication for billing practices and provide credentials for cloud operations. For this package, credentials are generally stored through a <em>dict</em> or <em>string</em>. Examples for credentials for the various services will be shown in the usage examples but the values should be replaced by yours!

```python
#example structure of aws/wasabi credentials
creds = {
    'aws_access_key_id': '<key_id>',
    'aws_secret_access_key': '<secret>',
    'region': 'us-east-1',
    }

#or digitalocean
creds = {
    'access_token': '<token>',
    'region': 'nyc3',
    }

```

# Local Testing

Some services may provide local emulators for rapid testing without the use of an internet connection. Using this is service dependant such as running the <em>AWS DymanoDB</em> local java engine. Take note of the <em>isLocalTest</em> argument to utilize this funtionality but remember to run the service's engine first!

# Service Responses

The returned information of cloud operations is dependant on the service. The returned object from these abstracted operations is generally polymorphic.

# Usage

The CloudManager currently provides 5 major abstractions seperated by sub-classes. Since <strong>AWS</strong> maintains the largest market share of providers (larger than Google and Microsoft combined) they have set many API standards. Some of these services are interchangable.


### CloudManager.IAM
A central focus of many cloud platforms is in managing access to the services themselves. This <strong>Identity Access Management</strong> abstraction is designed to work with <strong>AWS</strong> and <strong>Wasabi</strong>.
```python

#set the service provider
CloudManager.IAM.service = 'aws' #| 'wasabi'

#create a user
new_user = CloudManager.IAM.Create_User('user1',creds=creds)

#create access key for user
response = CloudManager.IAM.Generate_User_accesskey('user1',creds=creds)

#create a policy
actions = ['PutObject','GetObject']
resources = ['mybucket1/*','mybucket2']
policy_statement = CloudManager.IAM.Utils.Statementize('s3',actions,'Allow',resources)

#submit the new policy
new_policy_response = CloudManager.IAM.Create_Policy('test_policy','For testing purposes',[policy_statement],creds=creds)

#create a group
new_group = CloudManager.IAM.Create_Group('new_group',creds=creds)

#add user to group
user_was_added = CloudManager.IAM.Add_User_to_Group('new_group','user1',creds=creds)

#create a role
response = CloudManager.IAM.Create_Role('serverless_func_role','For serverless functions','lambda',creds=creds)

#attach policy to role
attached_response = CloudManager.IAM.Attach_Policy_to_Role('serverless_func_role','test_policy',creds=creds)

```

### CloudManager.NoSQLDatabase
This abstraction is designed for primary use with <strong>AWS DynamoDB</strong> and it is recommended to use this for fast read/write of smaller objects.

```python

#list any tables
tables = CloudManager.NoSQLDatabase.List_Tables(creds=creds)

#making a new table
tablename = 'new_table'

#define the table's hash and range keys/type
table_keys = {
    'hash': ['hash_att','S']
    'range': ['range_att','N']
    }

#create the table
resp = CloudManager.NoSQLDatabase.Create_Tables(tablename,table_keys,creds=creds)

#a new object to write
my_obj_as_dict = {
    'hash_att': 'A',
    'range_att': 5,
    'other_data': 2.45,
    }

#write a single object
resp = CloudManager.NoSQLDatabase.Write(my_obj_as_dict,tablename,creds=creds)

#reading an object from a NOSQL database requires the defining key
obj_key = my_obj_as_dict
#note: only need the attributes that define the hash/range, other data is not necessary

#call the read operation
obj_dict = CloudManager.NoSQLDatabase.Read(obj_key,tablename,creds=creds)

#there are also batch operations so many objects can be written
another_obj_dict_1 = {
    'hash_att': 'A',
    'range_att': 6,
    'other_data': 2.72,
    }
another_obj_dict_2 = {
    'hash_att': 'B',
    'range_att': 6,
    'other_data': 9.99,
    }

obj_list = []
obj_list.append(another_obj_dict_1)
obj_list.append(another_obj_dict_2)

#call the batch write operation
no_resp = CloudManager.NoSQLDatabase.BatchWrite(obj_list,tablename,creds=creds)

#what about reading multiple items? 
#dynamodb has both scanning and querying
#CAREFUL: these operations may cost significantly more time/$

#queries require a specified condition
condition = {} #or CloudManager.NoSQLDatabase.Condition().Dictify()
condition['hash_key_name'] = 'hash_att'
condition['hash_key_val'] = 'A'
condition['range_key_name'] = 'range_att'
condition['range_key_val'] = 5
condition['hash_op'] = '=' #must be
condition['range_op'] = '>=' #'begins_with' | 'between' | '=' | '<' | '<=' | '>' | '>='

#call the query operation
objs_returned = CloudManager.NoSQLDatabase.Query(tablename,condition,creds=creds)

#or just scan the whole table
all_objs = CloudManager.NoSQLDatabase.Scan_Table(tablename,creds)

```

### CloudManager.ObjectStorage
This abstraction is designed for primary use with <strong>Wasabi</strong> and it is recommended to use this for slower read/write of larger objects. Additionally, Wasabi currently uses the AWS S3 API protocols so AWS creds may be substituted; please note the <em>Rename</em> operation is unique to Wasabi while AWS S3 has the unique ability to mark buckets for hosting static websites.

```python

#pick a bucket
bucketname = 'my_new_bucket'

#call the create operation
resp = CloudManager.ObjectStorage.CreateBucket(bucketname,creds=creds)

#either in memory data or files may be uploaded
obj_as_str = 'maybe a json str'
filepath = './folder/file.ext'
objectname = 'test/object'

#call the upload for the in memory
resp = CloudManager.ObjectStorage.Upload(obj_as_str,bucketname,objectname,creds=creds)

#or directly upload file
resp = CloudManager.ObjectStorage.UploadFile(filepath,bucketname,objectname,creds=creds,forgetFileSecurity=True)

#download
obj_as_str = CloudManager.ObjectStorage.Download(bucketname,objectname,creds=creds,decodeBytes=True)

#NOTE: both upload/download have batch operations that use multithreading

#renaming may also be done directly with wasabi, ws s3 requires reuplading/deleting
#this is because wasabi provides additional functionality in order to remain atomic
new_objectname = 'test/new_object'

#call the rename operation
was_renamed = CloudManager.ObjectStorage.Rename(bucketname,objectname,new_objectname,creds=creds)

#another important usage is providing limited objectstorage to the public 
#through presigned operations that may expire
expiresec = 60 #expires in a minute

#presigned upload
presigned_post = CloudManager.ObjectStorage.Get_Upload_Url(bucketname,new_objectname,creds=creds,expiresec=expiresec)

#presigned downoad
presigned_GET_url = CloudManager.ObjectStorage.Get_Download_Url(bucketname,new_objectname,creds=creds,expiresec=expiresec)

```

### CloudManager.ServerlessFunctions
Serverless functions are microcompute units designed to execute very short run functions. Typical usage may either rely on invoking these cloud functions directly or by setting them up behind an API Gateway to create a RESTful API. Currently only <strong>AWS Lambda</strong> is available for this abstraction.

```python

#serverless functions are easily identified by name
func_name = 'my_serverless_func'

#the simplest function is written in a python script and requires a handling function denoted by name
func_handler = 'my_handler'

lambda_config = LambdaConfig({
	'func_name': func_name,
	'func_handler': func_handler,
	'purpose': 'For testing serverless functionality.',
	'role_name': 'serverless_func_role', #should already be created through IAM
	'runtime': 'python3.6',
	'func_filepath': './folder/my_script.py',
	'environment_name': 'test_env',
	'pip_requirements_list': ['numpy==1.14.5'], #boto3 is default? yes
	'sup_Filepaths_list': ['./data/some_data.csv'],
	'mem': 128,
	'timeout': 15,
	'overwrite': True,
	})

api_config = ApiConfig({
	'api_name': 'my_api',
	'purpose': 'For providing RESTful API to serverless function',
	'usage_name': 'usage1',
	'usage_purpose': 'Managing api usage',
	'usage_throttle_rate': 100.0,
	'usage_throttle_burst': 50,
	'usage_quota_limit': 50,
	'usage_quota_period': 'WEEK',
	'usage_quota_offset': 2,
	'key_name': 'testkey',
	'key_purpose': 'requiring api calls to provide key for access',
	'resource_name': 'resource',
	'http_method': 'GET',
	'stage_name': 'prod',
	'stage_purpose': 'testing production',
	'deployment_purpose': 'for front test',
	})

#deploy the function
#NOTE: because some packages require compilation before deployment, Docker is used and must be running beforehand
#please see Docker.Compile notes!
lambda_resp,_ = CloudManager.ServerlessFunctions.Deploy(lambda_config,api_config=api_config,creds=creds)

#invoking the function requires submitting a dict with the arguments to submit
argument_value = 12345
event = {
    'argument_name': argument_value,
    }

#call the invoke operation
resp = CloudManager.ServerlessFunctions.Invoke(func_name,event,creds=creds)

```

### CloudManager.Cluster

Clusters are macro compute resources - virtual cloud servers. Currently the main service is <strong>DigitalOcean</strong> as it is cheaper than <em>AWS EC2</em> but unfortunately, doesn't support GPU resources yet. Lastly, this toolset is designed to treat the virtual servers as a cluster where there is no centralized control - the software deployed to each is identical.


```python

#example DO creds
creds = {
    'access_token': '<token>',
    'region': 'nyc3',
    }

#before we deploy compute resources an asymmetric key is needed for SSH communicaiton
from security import Encrypting
asymKeys = Encrypting.Asymmetric.GenerateKey('my new keys',4)

#first step is to configure the cluster
cluster_config = ClusterConfig({
    'tag': 'test_cluster',
    'n_nodes': 3,
    'compute_task': '',
    'asymKeys': asymKeys,
    'OSimage': 'docker-18-04',
    'price_per_node': 20,
    'useMonitoring': False,
    'runtime': 'python3.6',
    'pip_requirements_list': ['numpy==1.14.5'],
    'sup_Filepaths_list': '',
    })

#deploy the cluster
compute_cluster,dependancy_zip_filePath = CloudManager.Cluster.Deploy(cluster_config,creds=creds)

#need to add an additional file?
CloudManager.Cluster.PutSupFile(compute_cluster,'./data/extra.csv',node_idz=[0,1,2])

#or add another node?
compute_cluster = CloudManager.Cluster.AddNode(compute_cluster,creds=creds,dependancy_zip_filePath=dependancy_zip_filePath)

#or send an arbitray command
CloudManager.Cluster.SendCommand(compute_cluster,'echo hello',node_idz=[0])
#note: responses are printed to console

```

# TODO:
* Many service responses are limited and may accept markers for pagination -> document and enable this in CloudManager
* Complete additional controls for digitalocean_service for furthering automation capabilities
* Major: complete service routers so eventually other services may be added such as Linode for Cluster, or Azure for Serverless
* AWS cloudfront and s3 static website hosting capabilities (augmenting the wasabi_service)
* Respectable testing procedures...

"""