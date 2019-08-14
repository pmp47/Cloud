#--start requirements--
#pip installs
import boto3
import botocore
from boto3.session import Session
from botocore.history import get_global_history_recorder

#customs

#builtins
import io
import urllib3
from copy import deepcopy
import logging

#--end requirements--

class Wasabi:
	"""Object interface for Wasabi S3-like API service.
	Args:
		wasabi_creds (dict): {
			'aws_access_key_id': '',
			'aws_secret_access_key': '',
			'region_name': ' #-> Not required as defaults to us-east-1
		}
	Ref:
		https://console.wasabisys.com/
	TODO:
		progres callbacks - https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3.html
	"""

	def __init__(self,wasabi_creds,resource='s3'):

		def move_object(self,**kwargs):
			"""Custom MoveObject S3 call. Exact copy of boto3 client._make_api_call but added to the params/model.
			Ref:
				https://wasabi.com/wp-content/themes/wasabi/docs/API_Guide/index.html#t=topics%2FRenaming_Objects.htm
				https://wasabi.com/wp-content/themes/wasabi/docs/API_Guide/index.html#t=topics%2FPUT_Object_Copy_Uses_Link.htm
			"""
			logger = logging.getLogger(__name__)
			history_recorder = get_global_history_recorder()

			operation_name = 'MoveObject'
			
			destination = kwargs.pop('NewKey')
			overwrite = kwargs.pop('Overwrite')
			quiet = kwargs.pop('Quiet')
			prefix = kwargs.pop('Prefix')
			api_params = kwargs
			api_params['CopySource'] = 'dummy/val' #not needed for move, but required by boto CopyObject that is to be modified
			operation_model = deepcopy(self._service_model.operation_model('CopyObject')) #steal the copyobject method and modify to be move
			operation_model.name = operation_name
			operation_model.http['method'] = 'MOVE'

			service_name = self._service_model.service_name
			history_recorder.record('API_CALL', {
				'service': service_name,
				'operation': operation_name,
				'params': api_params,
			})
			if operation_model.deprecated: logger.debug('Warning: %s.%s() is deprecated', service_name, operation_name)
			request_context = { 'client_region': self.meta.region_name,'client_config': self.meta.config,'has_streaming_input': operation_model.has_streaming_input,'auth_type': operation_model.auth_type,}
			request_dict = self._convert_to_request_dict(api_params, operation_model, context=request_context)
			
			#change the header
			request_dict['headers'].pop('x-amz-copy-source')
			request_dict['headers']['Destination'] = destination
			request_dict['headers']['Overwrite'] = str(overwrite)
			request_dict['headers']['X-Wasabi-Quiet'] = str(quiet)
			request_dict['headers']['X-Wasabi-Prefix'] = str(prefix)

			service_id = self._service_model.service_id.hyphenize()
			handler, event_response = self.meta.events.emit_until_response('before-call.{service_id}.{operation_name}'.format(service_id=service_id,operation_name=operation_name),model=operation_model, params=request_dict,request_signer=self._request_signer, context=request_context)

			if event_response is not None:
				http, parsed_response = event_response
			else:
				http, parsed_response = self._endpoint.make_request(operation_model, request_dict)

			self.meta.events.emit('after-call.{service_id}.{operation_name}'.format(service_id=service_id,operation_name=operation_name),http_response=http, parsed=parsed_response,model=operation_model, context=request_context)

			return parsed_response

		def add_custom_method(class_attributes, **kwargs):
			"""Injects the move_object function into boto3 runtime via extensibility:
			Ref:
				https://boto3.amazonaws.com/v1/documentation/api/latest/guide/events.html
			"""
			class_attributes['move_object'] = move_object
		
		#create a Session
		session = Session()

		#register the custom move_object injection
		session.events.register('creating-client-class.s3',add_custom_method)

		try: #wasabi didnt always have a region?
			region_name = kwargs['region_name']
		except:
			region_name = 'us-east-1'

		#configure the resource via credentials
		self.resource = session.resource(resource,endpoint_url='https://' + resource + '.wasabisys.com',aws_access_key_id=wasabi_creds['aws_access_key_id'],aws_secret_access_key=wasabi_creds['aws_secret_access_key'],region_name=region_name)

		return super().__init__()

	class Object:
		"""Object specific functions.
		TODO:
			Add in returning size, datemodified
		"""
		
		#resp = wasabi.resource.meta.client.head_object(Bucket=bucketname,Key=objectName)
		#resp['ContentLength']
		#resp['LastModified']

		def Upload(wasabi,obj_as_str: str,bucketname: str,objectName: str):
			"""Upload a string of data as an object.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				obj_as_str (str): Object to upload as a string of data.
				bucketname (str): Name of specified bucket to store object.
				objectname (str): Name or filepath inside a bucket of the object.
			Returns:
				dict: response from server.
			"""
			f = io.BytesIO(obj_as_str.encode('utf-8'))
			f.seek(0)
			return wasabi.resource.meta.client.upload_fileobj(f,Bucket=bucketname,Key=objectName)

		def UploadFile(wasabi,filePath: str,bucketname: str,objectName: str):
			"""Upload an object from a local filepath.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				filePath (str): Object to upload designated by local filepath.
				bucketname (str): Name of specified bucket to store object.
				objectname (str): Name or filepath inside a bucket of the object.
			Returns:
				dict: response from server.
			"""
			return wasabi.resource.meta.client.upload_file(Filename=filePath,Bucket=bucketname,Key=objectName)

		def Download(wasabi,bucketname: str,objectName: str):
			"""Download an object as a string of data.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				bucketname (str): Name of specified bucket of object to download.
				objectname (str): Name or filepath inside a bucket of the object.
			Returns:
				str: object data.
			"""
			obj = wasabi.resource.Object(bucketname, objectName)
			return obj.get()['Body'].read()

		def Delete(wasabi, bucketname: str, objectName: str):
			"""Delete an object as a string of data.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				bucketname (str): Name of specified bucket of object to download.
				objectname (str): Name or filepath inside a bucket of the object.
			Returns:
				dict: Response from server.
			"""
			obj = wasabi.resource.Object(bucketname, objectName)
			return obj.delete()

		def Rename(wasabi,bucketname: str,old_objectName: str,new_objectName: str,overwrite: bool,quiet: bool,folders: bool):
			"""Rename an object by changing its key.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				bucketname (str):
				old_objectName (str): 
				new_objectName (str):
				overwrite (bool):
				quiet (bool): Causes the XML status return body to only display the keys that encounter errors.
				folders (bool): False to only rename the objects (including all ver­sions) that exactly match the key.
			Returns:
				dict: Response from server.
			Ref:
				https://wasabi.com/wp-content/themes/wasabi/docs/API_Guide/index.html#t=topics%2FRenaming_Objects.htm
			Notes:
				Documentation notes s3:PubObject ACL permission required, however this was insufficient. 
				Most likely requires additional PutObject*, DeleteObject* for changing the meta tags
			"""
			
			#TODO: change bucket too?
			return wasabi.resource.meta.client.move_object(Bucket=bucketname,Key=old_objectName,NewKey=new_objectName,\
					Overwrite=overwrite,Quiet=quiet,Prefix=folders)

		def Generate_Download_Url(wasabi,bucketname: str,objectName: str,expiresec=100):
			"""Generate a presigned url to download an object.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				bucketname (str): Name of specified bucket of object to download.
				objectname (str): Name or filepath inside a bucket of the object.
				expiresec (int): Seconds until the presigned authorization expires.
			Returns:
				str: presigned_get_url
			"""
			return wasabi.resource.meta.client.generate_presigned_url('get_object',Params={'Bucket':bucketname,'Key':objectName},ExpiresIn=expiresec)

		def Generate_Upload_Url(wasabi,bucketname: str,objectName: str,expiresec=100):
			"""Generate a presigned url for uploading an object.
			Args:
				wasabi (Wasabi): Wasabi session interface.
				bucketname (str): Name of specified bucket to store object.
				objectname (str): Name or filepath inside a bucket of the object.
				expiresec (int): Seconds until the presigned authorization expires.
			Returns:
				dict: presigned post.
			"""
			# Make sure everything posted is NOT publicly readable
			fields = {'acl': 'private'} #ACL='private'|'public-read'|'public-read-write'|'authenticated-read'|'aws-exec-read'|'bu
			# Ensure that the ACL isn't changed
			conditions = [
				{'acl': 'private'},
				#["content-length-range", 10, 100] #TODO: limit size?
			]
			return wasabi.resource.meta.client.generate_presigned_post(Bucket=bucketname,Key=objectName,Fields=fields,Conditions=conditions,ExpiresIn=expiresec)

		def Exists(wasabi,bucketname: str, objectName: str):
			"""Checks if an object exists in a bucket.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
				bucketname (str): Name of specified bucket to check for object.
				objectname (str): Name or filepath inside a bucket of the object.
			Returns:
				bool: True if object exists in bucket.
			"""
			try:
				resp = wasabi.resource.Object(bucketname,objectName).load() #this doesnt download? nah thats .get
				return True
			except botocore.exceptions.ClientError as e:
				if e.response['Error']['Code'] == '404': # The object does not exist.
					return False
				else: # Something else has gone wrong.
					raise ValueError('Failed to check if object exists')

	class Bucket:
		"""Bucket specific functions.
		"""

		def Create(wasabi,buckname: str):
			"""Creates a bucket.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
				bucketname (str): Name of specified bucket to create.
			Returns:
				dict: Response from server.
			"""
			return wasabi.resource.meta.client.create_bucket(Bucket=buckname)

		def Delete(wasabi,buckname: str):
			"""Deletes a bucket.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
				bucketname (str): Name of specified bucket to delete.
			Returns:
				dict: Response from server.
			"""
			return wasabi.resource.meta.client.delete_bucket(Bucket=buckname)

		def ListObjects(wasabi,bucketname: str,prefix = '/'):
			"""List objects in a bucket.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
				bucketname (str): Name of specified bucket to list.
			Returns:
				list: List of objects as dicts.
			"""

			if prefix[-1] != '/': prefix = prefix + '/'

			resp = wasabi.resource.meta.client.list_objects(Bucket=bucketname,MaxKeys=1000,Prefix=folderpath,Delimiter='/')
			try:
				objs = resp['Contents']
			except:
				objs = []
			didnt_get_all = resp['IsTruncated']
			while didnt_get_all:
				resp = wasabi.resource.meta.client.list_objects(Bucket=bucketname,MaxKeys=1000,Prefix=folderpath,Delimiter='/',\
					Marker=resp['Contents'][-1]['Key']) #use last key as next marker
				obj_list = obj_list + resp['Contents']
				didnt_get_all = resp['IsTruncated']

			return obj_list

		def List(wasabi):
			"""List all buckets.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
			Returns:
				dict: Response from server.
			"""
			return wasabi.resource.meta.client.list_buckets()

		def Empty(wasabi,bucketname: str,objects: dict):
			"""Empty a bucket by mass deleting objects inside.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
				bucketname (str): Name of specified bucket to empty.
				objects (dict): {'Objects':objects}; objects.append({'Key': key})
			Returns:
				dict: Resposne from server.
			"""
			return wasabi.resource.meta.client.delete_objects(Bucket=bucketname,Delete=objects)

		def ListDir(wasabi,bucketname: str,folderpath: str):
			"""List objects in a bucket within a folderpath.
			Args:
				wasabi (Wasabi): Instantiated credential interface.
				bucketname (str): Name of specified bucket to list.
				folderpath (str): Folderpath prefix.
			Returns:
				list: List of object keys.
			"""

			folderpath.replace('//','/')
			if folderpath[-1] != '/': folderpath = folderpath + '/'
			prefix = folderpath
			delimiter = '/'

			objs = []
			folders = []
			resp = wasabi.resource.meta.client.list_objects(Bucket=bucketname,MaxKeys=1000,Prefix=prefix,Delimiter=delimiter)
			try:
				objs = objs + resp['Contents']
			except:
				objs = []

			try:
				folders = folders + resp['CommonPrefixes']
			except:
				folders = []

			didnt_get_all = resp['IsTruncated']
			while didnt_get_all:
				resp = wasabi.resource.meta.client.list_objects(Bucket=bucketname,Prefix=folderpath,MaxKeys=1000,Delimiter='/',Marker=resp['Contents'][-1]['Key']) #use last key as next marker
				try:
					objs = objs + resp['Contents']
				except:
					objs = []

				try:
					folders = folders + resp['CommonPrefixes']
				except:
					folders = []
				didnt_get_all = resp['IsTruncated']

			for obj in range(len(objs)):
				objs[obj] = objs[obj]['Key'].split(prefix)[-1]

			for folder in folders:
				val = folder['Prefix'].split(prefix)[-1]
				if val != '/':
					objs.append(val)

			#remove ''?
			return list(filter(None,objs))

class Tests:
	
	def main():

		pass