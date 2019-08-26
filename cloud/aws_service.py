#--start requirements--
#pip installs
import boto3
import botocore
from boto3.dynamodb.conditions import Key, Attr

#customs

#builtins
import uuid
import zipfile
import os
import json
import copy

#--end requirements--


class AWS:
	"""Class to manage Amazon Web Services.
	"""

	def preptag(tag):
		"""Requires tag to start/end with '/'
		Args:
			tag (str):
		Returns str: tag
		"""
		if (tag[0] != '/'):
			tag = '/' + tag
		if (tag[-1] != '/'):
			tag = tag + '/'
		return tag

	class DynamoDB:
		"""For managing DynamoDB.
		Args:
			aws_creds (dict):
			isLocalTest (bool):
		Ref:
			http://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html
			https://aws.amazon.com/dynamodb/pricing/
			https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html
		Notes:
			First 25 GB consumed per month is free, and prices start from $0.25 per GB-month thereafter.
			Pricing is more dependant on speed of access:
			
			
		DynamoDB                                Python
		--------                                ------
		{'NULL': True}                          None
		{'BOOL': True/False}                    True/False
		{'N': str(value)}                       Decimal(str(value))
		{'S': string}                           string
		{'B': bytes}                            Binary(bytes)
		{'NS': [str(value)]}                    set([Decimal(str(value))])
		{'SS': [string]}                        set([string])
		{'BS': [bytes]}                         set([bytes])
		{'L': list}                             list
		{'M': dict}                             dict

		"""

		def __init__(self,aws_creds: dict,isLocalTest: bool):
			try:
				if isLocalTest:
					self.resource = boto3.resource('dynamodb',\
						aws_access_key_id = '',
						aws_secret_access_key = '',
						region_name = '',
						endpoint_url='http://localhost:8000')
				else:
					self.resource = boto3.resource('dynamodb',\
						aws_access_key_id = aws_creds['aws_access_key_id'],
						aws_secret_access_key = aws_creds['aws_secret_access_key'],
						region_name=aws_creds['region'])
			except:
				#for if a service using a role, creds wont be specified
				self.resource = boto3.resource('dynamodb')
			return super().__init__()
			
		class Table:
			"""For managing Table functions.
			"""

			def List(dynamodb,start_name='',limit=100):
				"""List all Tables.
				Args:
					dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
					start_name (str):
					limit (int):
				Returns:
					list: List of tablenames.
				"""
				if start_name != '':
					return dynamodb.resource.meta.client.list_tables(ExclusiveStartTableName=start_name,Limit=limit)['TableNames']
				else:
					return dynamodb.resource.meta.client.list_tables()['TableNames']

			def Create(dynamodb,tablename: str,hashkey: str,hashkey_type='S',rangekey='',rangekey_type='S',provision={'read':1,'write':1}):
				"""Create a new table. Does not overwrite so check the description.
				Args:
					dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
					tablename (str): Name of table to create.
					hashkey (key): Attribute of object's primary unique hashkey.
					hashkey_type (str): Type of the attribute: 'S'|'N'     |'M'?
					rangekey (key): Attribute of object's secondary non-unique rangekey.
					rangekey_type (str): Type of the attribute: 'S'|'N'     |'M'?
					provision (dict): Keys are 'read','write' and are ints describing throughput units to provision for table.
				Returns:
					dict: table's description.
				"""

				if hashkey == rangekey:
					raise ValueError('Must have a hashkey, and must not have identical range and hash keys.')

				try:
					#create key scheme
					key_schema=[
							{
								'AttributeName': hashkey,
								'KeyType': 'HASH'
							}
						]
					#create attribute definitions
					attribute_definitions=[
							{
								'AttributeName': hashkey,
								'AttributeType': hashkey_type
							}
						]

					#if range key is provided, add it as a key and attribute
					if rangekey != '':
						key_schema.append(
							{
								'AttributeName': rangekey,
								'KeyType': 'RANGE'
							})
						attribute_definitions.append({
								'AttributeName': rangekey,
								'AttributeType': rangekey_type
							})

					#use client to create table
					return dynamodb.resource.meta.client.create_table(
						TableName = tablename,
						KeySchema = key_schema,
						AttributeDefinitions = attribute_definitions,
						ProvisionedThroughput = {
							'ReadCapacityUnits': provision['read'],
							'WriteCapacityUnits': provision['write']
						})['TableDescription']
				except Exception as ex:
					#will throw exception if table already created, so return its description
					return dynamodb.resource.meta.client.describe_table(TableName=tablename)['Table']
						
			def Describe(dynamodb,tablename: str):
				"""Describe a Table specified by name.
				Args:
					dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
					tablename (str): Name of the table to describe.
				Returns:
					dict: table's description.
				"""
				return dynamodb.resource.meta.client.describe_table(TableName=tablename)['Table']

			def Delete(dynamodb,tablename: str):
				"""Delete a Table specified by name.
				Args:
					dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
					tablename (str): Name of the table to delete.
				Returns:
					dict: server response.
				"""
				return dynamodb.resource.meta.client.delete_table(TableName=tablename)

			def Scan(dynamodb,tablename: str):
				"""Scan an entire table.
				Args:
					dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
					tablename (str): Name of the table to scan.
				Returns:
					list: items scanned.
				Note:
					This can incur large provision throughput and be costly.
				"""

				response = dynamodb.resource.Table(tablename).scan()
				data = response['Items']

				while response.get('LastEvaluatedKey'):
					response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
					data.extend(response['Items'])
				return data

			def UpdateTTL(dynamodb,tablename: str,enabled: bool,attributename: str):
				"""Update the Time-To-Live status/attribute of a specified table.
				Args:
					dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
					tablename (str): Name of the table to scan.
					enabled (bool): True if TTL is to be enabled.
					attributename (str): Name of the TTL epoch attribute of the objects.
				Returns:
					dict: server response.
				Ref:
					https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Client.update_time_to_live
				"""
				ttl_spec = {
					'Enabled': enabled,
					'AttributeName': attributename
					}
				return dynamodb.resource.meta.client.update_time_to_live(TableName=tablename,TimeToLiveSpecification=ttl_spec)

		def Write(dynamodb,obj_as_dict: dict,tablename: str):
			"""Writes an object as a dict to a table.
			Args:
				dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
				obj_as_dict (dict): An object represented as a dict.
				tablename (str): Name of the table to write the object.
			Returns:
				dict: server response.
			"""
			return dynamodb.resource.Table(tablename).put_item(Item=obj_as_dict)

		def BatchWrite(dynamodb,obj_list: list,tablename: str):
			"""Writes a list of objects as a dict to a table.
			Args:
				dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
				obj_list (list): A list of objects represented as a dict.
				tablename (str): Name of the table to write the object.
			Returns:
				None
			"""

			#TODO: use batch_writer if need to do many writes to save consumption
			#http://boto3.readthedocs.io/en/latest/guide/dynamodb.html#using-an-existing-table
			with dynamodb.resource.Table(tablename).batch_writer() as batch:
				for obj_as_dict in obj_list:
					batch.put_item(Item=obj_as_dict)
			return None

		def ChangeKeyValue(dynamodb,obj_as_dict: dict,tablename: str,keys: dict,new_vals: list):
			"""Changes an objects recorded key value by doing a transactional delete and rewrite.
			Args:
				dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
				obj_as_dict (dict): An object represented as a dict.
				tablename (str): Name of the table to write the object.
				keys (dict): 
				new_vals (list): [new_hash_val,new_range_val], None or '' if not changing
			Returns:
				dict: server_response
			"""
				
			new_obj = copy.deepcopy(obj_as_dict)
			if (new_vals[0] != None):
				new_obj[keys['hash'][0]] = new_vals[0]
			if (new_vals[1] != None):
				new_obj[keys['range'][0]] = new_vals[1]

			old_key = {keys['hash'][0]: obj_as_dict[keys['hash'][0]]}
			if keys['range'] != None:
				old_key[keys['range'][0]] = obj_as_dict[keys['range'][0]]

			response = dynamodb.resource.meta.client.transact_write_items(
				TransactItems=[
					{
						'Delete': {
							'Key': old_key,
							'TableName': tablename,
							'ReturnValuesOnConditionCheckFailure': 'NONE'
							},
						},
					{
						'Put': {
							'Item': new_obj,
							'TableName': tablename,
							'ReturnValuesOnConditionCheckFailure': 'NONE'
							},
						},
					]
				)

			return response

		def Read(dynamodb,keys: dict,tablename: str):
			"""Reads an obj from a table.
			Args:
				dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
				keys (dict): Dict of the hashkey and rangekey if necessary.
				tablename (str): Name of the table where the object is.
			Returns:
				dict: object as a dict.
			"""
			return dynamodb.resource.Table(tablename).get_item(Key=keys)['Item']

		def Erase(dynamodb,keys: dict,tablename: str):
			"""Erase an item from a table.
			Args:
				dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
				keys (dict): Dict of the hashkey and rangekey if necessary.
				tablename (str): Name of the table where the object is.
			Returns:
				dict: server response.
			"""
			return dynamodb.resource.Table(tablename).delete_item(Key=keys)

		def Query(dynamodb,condition: dict,tablename: str):
			"""Query a table for items based on key conditions.
			Args:
				dynamodb (DynamoDB): Instantiated DynamoDB credential access object.
				condition (dict):
					condition['hash_key_name'] = 'yourhashkey'
					condition['hash_key_val'] = 'uniquehashkeyvalue'
					condition['range_key_name'] = 'rangekey'
					condition['range_key_val'] = 'rangekeyvalue'
					condition['hash_op'] = '=' #must be
					condition['range_op'] = 'begins_with' | 'between' | '=' | '<' | '<=' | '>' | '>='
				tablename (str):
			Returns:
				dict: response from server.
			"""
			def any(n,chars):
				kce = Key(n).begins_with(chars[0])
				for c in range(1,len(chars)):
					kce = kce & Key(n).begins_with(chars[c])
				return kce

			ops = {
				'=': lambda n,v: Key(n).eq(v),
				'<': lambda n,v: Key(n).lt(v),
				'<=': lambda n,v: Key(n).lte(v),
				'>': lambda n,v: Key(n).gt(v),
				'>=': lambda n,v: Key(n).gte(v),
				'begins_with': lambda n,v: Key(n).begins_with(v),
				'between': lambda n,v: Key(n).between(v[0],v[1]),
				#'contains': lambda n,v: Key(n).
				#'any': lambda n,v: any(n,v) #KeyConditionExpressions must only contain one condition per key
				}
			#TODO: The result set from a Query is limited to 1 MB per call. You can use the LastEvaluatedKey from the query response to retrieve more results. 
			return dynamodb.resource.Table(tablename).query(\
				KeyConditionExpression=ops[condition['hash_op']](condition['hash_key_name'],condition['hash_key_val']) & \
				ops[condition['range_op']](condition['range_key_name'],condition['range_key_val']))

	class CostExplorer:
		"""For managing cost explorer.
		Args:
			aws_creds (dict):
		Notes:
			This service costs $0.01 per request.
		Ref:
			http://boto3.readthedocs.io/en/latest/reference/services/ce.html
			https://aws.amazon.com/aws-cost-management/pricing/
			"""

		def __init__(self,aws_creds: dict):

			#configure the seesion via credentials
			try:
				self.session = boto3.Session(
					aws_access_key_id = aws_creds['aws_access_key_id'],
					aws_secret_access_key = aws_creds['aws_secret_access_key'])
				self.client = self.session.client('ce')
			except:
				self.client = boto3.client('ce')

			return super().__init__()

		def Get_Cost_Usage(cost_explorer,start: str,end: str):
			"""Get basic cost/usage for AWS between start/end dates. (inclusive/exclusive)
			Args:
				cost_explorer (CostExplorer): Instantiated CostExplorer credential access object.
				start (str): '2018-06-01'
				end (str): '2018-07-01'
			Returns:
				dict: response
			TODO: 
				Add filtering so may tag resources per project and account on a per project basis
			"""

			timePeriod = {
				'Start': start,
				'End': end,
				}

			granularity = 'MONTHLY'

			metrics = ['AmortizedCost','BlendedCost','UsageQuantity']
				
			groupby = [
				{
					'Type': 'DIMENSION',
					'Key': 'SERVICE'
				}]

			raise ValueError('This service costs $0.01 per request')
			response = cost_explorer.client.get_cost_and_usage(
				TimePeriod = timePeriod,
				Granularity = granularity,
				Metrics = metrics,
				GroupBy = groupby
				)

			return response

	class APIGateway:
		"""Class for managing API Gateway
		Args:
			aws_creds (dict):
		Ref:
			https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html
		TODO:
			https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html
		"""

		def __init__(self,aws_creds):

			#configure the seesion via credentials
			self.session = boto3.Session(
				aws_access_key_id = aws_creds['aws_access_key_id'],
				aws_secret_access_key = aws_creds['aws_secret_access_key']
			)
				
			self.client = self.session.client('apigateway',region_name=aws_creds['region'])
			self.region = aws_creds['region']

			return super().__init__()
			
		def List(apig):
			"""List all APIs in region.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
			Returns:
				list: api dicts.
			"""
			return apig.client.get_rest_apis()['items']

		def GetId(apig,api_name: str):
			"""Get the ID of an API specified by name.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
				api_name (str): Name of specified API.
			Returns:
				string: api_id
			"""
			rest_api_list = AWS.APIGateway.List(apig)

			api_id = ''
			for api in rest_api_list:
				if api['name'] == api_name:
					api_id = api['id']
			return api_id

		def Create(apig,api_name: str,purpose: str,overwrite=False,rest_type='EDGE',apikeysource='HEADER'):
			"""Creates a REST Api.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
				api_name (str): Name of the API.
				purpose (str): Reason for making API.
				overwrite (bool): True if to overwrite an API that already exists.
				rest_type (str): 'REGIONAL'|'EDGE'|'PRIVATE'
				apikeysource (str): 'HEADER'|'AUTHORIZER' ('x-api-key' or UsageIdentifierKey)
			Returns:
				dict: Server response.
			Note:
				If overwrite is True, will overwrite an existing API. If not, then will return the information of that API.
			Ref:
				https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway.html#APIGateway.Client.create_rest_api
			"""

			#TODO: binaryMediaTypes=['string'] utf-8 default
			#version='string'
			#cloneFrom='string'
			#policy='string'
			#minimumCompressionSize=123

			#see if api exists already
			rest_api_list = AWS.APIGateway.List(apig)

			active_apis = [x for x in rest_api_list if x['name'] == api_name]

			if len(active_apis) <= 0: #not already an active api
				return apig.client.create_rest_api(
					name=api_name,
					description=purpose,
					apiKeySource=apikeysource,
					endpointConfiguration={'types': [rest_type]})
			else: #already exists
				if overwrite: #overwrite through update
					return AWS.APIGateway.Update(apig,active_apis[0]['id'],purpose,rest_type,apikeysource)
				else:
					return active_apis[0]

		def Update(apig,api_id: str,purpose: str,rest_type: str,apikeysource: str):
			"""Update an API.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
				api_id (str): The id of the API.
				purpose (str): Reason for making API.
				rest_type (str): 'REGIONAL'|'EDGE'|'PRIVATE'
				apikeysource (str): 'HEADER'|'AUTHORIZER' ('x-api-key' or UsageIdentifierKey)
			Returns:
				dict: server reponse.
			"""

			apis = AWS.APIGateway.List(apig)
			for api in apis:
				if api['id'] == api_id:
					current_rest_type = api['endpointConfiguration']['types'][0]
			response = apig.client.update_rest_api(
				restApiId=api_id,
				patchOperations=[
					{
						'op': 'replace',
						'path': '/description',
						'value': purpose,
					},
					{
						'op': 'replace',
						'path': '/endpointConfiguration/types/' + current_rest_type,
						'value': rest_type,
					},
					{
						'op': 'replace',
						'path': '/apiKeySource',
						'value': apikeysource,
					}
				]
			)
			return response

		def Delete(apig,api_name: str):
			"""Delete a REST Api by name.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
				api_name (str): Name of API to be deleted.
			Returns:
				dict: server response.
			"""
			api_id = AWS.APIGateway.GetId(apig,api_name)
			return apig.client.delete_rest_api(restApiId=api_id)

		def Deploy(apig,api_id: str,stage_name: str,stage_purpose: str,deployment_purpose: str):
			"""Stage a deployment of an API.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
				api_id (str): API specified by Id.
				stage_name (str): Name of this deployment stage.
				stage_purpose (str): Why this deployment stage is created.
				deployment_purpose (str): Why this API is being deployed.
			Returns:
				dict: response from server.
			"""

			response = apig.client.create_deployment(
				restApiId=api_id,
				stageName=stage_name,
				stageDescription=stage_purpose,
				description=deployment_purpose,
				#cacheClusterEnabled=True|False,
				#cacheClusterSize='0.5'|'1.6'|'6.1'|'13.5'|'28.4'|'58.2'|'118'|'237',
				#variables={
				#	'string': 'string'
				#},
				#canarySettings={
				#	'percentTraffic': 123.0,
				#	'stageVariableOverrides': {
				#		'string': 'string'
				#	},
				#	'useStageCache': True|False
				#},
				#tracingEnabled=True|False
			)
			return response

		def Create_Stage(apig,api_id: str,deployment_id: str,stage_name: str,stage_purpose: str):
			"""Create a stage for a deployed API.
			Args:
				apig (APIGateway): Instantiated APIGateway credential access object.
				api_id (str): API specified by Id.
				deployment_id (str): Deployment specified by Id.
				stage_name (str): Name of this deployment stage.
				stage_purpose (str): Why this deployment stage is created.

			"""
			#TODO:  why does deployment also need the stagename?

			stages_response = apig.client.get_stages(
				restApiId=api_id,
				deploymentId=deployment_id
			)['item']

			stages = [x for x in stages_response if x['stageName'] == stage_name]

			#if stage already exists, return it
			if len(stages) <= 0:

				response = apig.client.create_stage(
						restApiId=api_id,
						stageName=stage_name,
						deploymentId=deployment_id,
						description=stage_purpose,
					)
			else:
				response = stages[0]

			return response

		class Resource:
			"""Sub class for managing a APIGateway Resource.
			"""

			def List(apig,api_name: str,embed=['methods']):
				"""List all resources in a specified API.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					api_name (str): Name of API to lsit resources of.
					embed (list): ?
				Returns:
					dict: server_response
				"""
				api_id = AWS.APIGateway.GetId(apig,api_name)
				return apig.client.get_resources(restApiId=api_id,embed=embed)['items']

			def Create(apig,api_name: str,name: str,parent_name='/'):
				"""Creates a resource for an API.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					api_name (str): Name of API to create resource for.
					name (str): Name of the resource to create.
					parent_name (str): Name of a parent resource to nest this as child.
				Returns:
					dict: resposne from server.
				TODO: 
					Return rest api id from list so dont have to call list twice (its called in resource list too)
					What about CORs?
				"""

				#get rest api id from name
				api_id = AWS.APIGateway.GetId(apig,api_name)

				#get resource list to get parent_id from parent_name
				resource_list = AWS.APIGateway.Resource.List(apig,api_name)

				#TODO: check if resource exists already? wont make duplicates?
				resource_id = ''
				for resource in resource_list:
					if resource['path'] == (parent_name + name):
						return resource #return existing resource
					if parent_name != '/':
						if resource['pathPart'] == parent_name:
							resource_id = resource['id']
					else:
						if resource['path'] == parent_name:
							resource_id = resource['id']
				return apig.client.create_resource(restApiId=api_id,parentId=resource_id,pathPart=name)

			def Delete(apig,api_name: str,resource_name: str):
				"""Deletes a resource for an API.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					api_name (str): Name of specified API.
					resource_name (str): Name of specified resouce to delete.
				Returns:
					dict: response from server.
				TODO: 
					Return rest api id from list so dont have to call list twice (its called in resource list too)
				"""
				
				#get rest api list to get api_id from name
				api_id = AWS.APIGateway.GetId(apig,api_name)

				resource_list = AWS.APIGateway.Resource.List(apig,api_name)

				resource_id = ''
				for resource in resource_list:
					if resource['pathPart'] == resource_name:
						resource_id = resource['id']

				return apig.client.delete_resource(restApiId=api_id,resourceId=resource_id)

		class Method:
			"""Sub class for managing Methods for REST Api Resources.
			"""

			def Get(apig,api_name: str,resource_name: str,http_method: str,parent_name='/'):
				"""Gets a Resource Method.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					api_name (str): Name of API.
					resource_name (str): Name of the resource.
					http_method (str): 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS'|'ANY'
					parent_name (str): Name of the parent resource.
				Returns:
					dict: method.
				"""

				api_id = AWS.APIGateway.GetId(apig,api_name)

				resource_list = AWS.APIGateway.Resource.List(apig,api_name)

				resource_id = ''
				for resource in resource_list:
					try:
						if resource['pathPart'] == resource_name:
							resource_id = resource['id']
					except:
						#not all resources have a path part (like / root)
						a = 5

				response = apig.client.get_method(
					restApiId=api_id,
					resourceId=resource_id,
					httpMethod=http_method)

				return response

			def Create(apig,api_name: str,resource_name: str,http_method: str,parent_name='/',key_req=True,authorizationtype='NONE',req_model={'application/json':'Empty'}):
				"""Creates a Resource Method.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					api_name (str): Name of the API.
					resource_name (str): Name of the resource.
					http_method (str): 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS'|'ANY'
					key_req (bool): True to require an API key to access.
					authorizationtype (str): 'NONE'.
					req_model (dict): {'application/json':'Empty'}
				Returns:
					dict: server reponse
				"""

				api_id = AWS.APIGateway.GetId(apig,api_name)

				try:
					method = AWS.APIGateway.Method.Get(apig,api_name,resource_name,http_method,parent_name)
					if method['ResponseMetadata']['HTTPStatusCode'] == 200:
						return method
				except:
					a = 5

				resource_list = AWS.APIGateway.Resource.List(apig,api_name)

				resource_id = ''
				for resource in resource_list:
					try:
						if resource['pathPart'] == resource_name:
							resource_id = resource['id']
					except:
						a = 5

				#resp_model = {'200':{'responseModels':{'application/json':'Empty'},'statusCode':'200'}}
				#authorizerId='string',
				#operationName='string',
				#requestParameters={'string': True|False},
				#requestValidatorId='string',
				#authorizationScopes=['string']
				return apig.client.put_method(
					restApiId=api_id,
					resourceId=resource_id,
					httpMethod=http_method,
					authorizationType=authorizationtype,
					apiKeyRequired=key_req,
					requestModels=req_model)

			def Add_Integration(apig,api_name: str,resource_id: str,http_method: str,lambda_arn: str,integration_type='AWS',enable_CORs=True):
				"""Adds an Lambda Function Integration to a Resource Method.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					api_name (str): API specified by name.
					resource_id (str): Resource Id.
					http_method (str): 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS'|'ANY'
					lambda_arn (str): ARN of the lambda function
					integration_type (str): 'HTTP'|'AWS'|'MOCK'|'HTTP_PROXY'|'AWS_PROXY'
					enable_CORs (bool): Default True enables CORs so lambda functions may be invoked AND x-api-key headers accepted for auth
				Returns:
					dict: server respnse
				Ref:
					http://boto3.readthedocs.io/en/latest/reference/services/apigateway.html#APIGateway.Client.put_integration
					https://github.com/boto/boto3/issues/572
					https://stackoverflow.com/questions/38052953/automating-cors-using-boto3-for-aws-api-gateway
				Notes:
					Enabling CORs is required to use API for invoking lambda function. 
				"""

				#get the id of the api by name
				api_id = AWS.APIGateway.GetId(apig,api_name)

				#get the version to use for the method integration
				#version = apig.client.meta.service_model.api_version
				version = '2015-03-31' #latest 2015-07-09 failed to properly invoke lambda

				#remove the latest alias funciton tag
				#TODO: why? - didnt work otherwise
				lambda_arn = lambda_arn.replace(':$LATEST','')
				
				#build the lambda uri
				uri = 'arn:aws:apigateway:' + apig.region + ':lambda:path/' + version + '/functions/' + lambda_arn + '/invocations'
				#uri arn:aws:apigateway:$REGION:lambda:path/2015-03-31/functions/arn:aws:lambda:$REGION:$ACCOUNT:function:LambdaFunctionOverHttps/invocations

				if enable_CORs:
					
					#add integration
					add_response = apig.client.put_integration(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod=http_method,
						integrationHttpMethod='POST',#http_method, #must change to POST as this is how lambda functions are invoked?
						uri=uri,
						type=integration_type)

					#add the method response
					method_response = apig.client.put_method_response(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod=http_method,
						statusCode='200',
						responseParameters={
							'method.response.header.Access-Control-Allow-Origin': False
						},
						responseModels={
							'application/json': 'Empty'
						})

					#add the integration response
					integration_response = apig.client.put_integration_response(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod=http_method,
						statusCode='200',
						responseParameters={
							'method.response.header.Access-Control-Allow-Origin': '\'*\''
						},
						responseTemplates={
							'application/json': ''
						}
					)

					#add an OPTION method
					option_response = apig.client.put_method(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod='OPTIONS',
						authorizationType='NONE'
					)

					# Set the put integration of the OPTIONS method
					opt_int_response = apig.client.put_integration(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod='OPTIONS',
						type='MOCK',
						requestTemplates={
							'application/json': '{"statusCode": 200}'
						}
					)

					# Set the put method response of the OPTIONS method
					opt_resp_response = apig.client.put_method_response(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod='OPTIONS',
						statusCode='200',
						responseParameters={
							'method.response.header.Access-Control-Allow-Headers': False,
							'method.response.header.Access-Control-Allow-Origin': False,
							'method.response.header.Access-Control-Allow-Methods': False
						},
						responseModels={
							'application/json': 'Empty'
						}
					)

					# Set the put integration response of the OPTIONS method
					opt_int_resp_response = apig.client.put_integration_response(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod='OPTIONS',
						statusCode='200',
						responseParameters={
							'method.response.header.Access-Control-Allow-Headers': '\'Content-Type,X-Amz-Date,Authorization,X-Api-Key,x-api-key,X-Amz-Security-Token\'',
							'method.response.header.Access-Control-Allow-Methods': '\'' + http_method + ',OPTIONS\'',
							'method.response.header.Access-Control-Allow-Origin': '\'*\''
						},
						responseTemplates={
							'application/json': ''
						}
					)

				else:

					add_response = apig.client.put_integration(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod=http_method,
						integrationHttpMethod=http_method,
						uri=uri,
						type=integration_type)

					resp_response = apig.client.put_integration_response(
						restApiId=api_id,
						resourceId=resource_id,
						httpMethod=http_method,
						statusCode='200',
						selectionPattern=''
					)

					# create POST method response
					try:
						method_response = apig.client.put_method_response(
							restApiId=api_id,
							resourceId=resource_id,
							httpMethod=http_method,
							statusCode='200',
							responseModels={
								'application/json': 'Empty' #TODO: make like in console
							})
					except:
						a = 5
						#TODO: update because http_method could change?

				return add_response

		class UsagePlan:
			"""Sub class for managing a UsagePlan
			TODO:
				Remove_Stage
				update, with remaining options like quota/throttle etc
			"""

			def List(apig):
				"""List all usage plans.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
				Returns:
					list: List of usage plans.
				"""
				return apig.client.get_usage_plans()['items']

			def GetId(apig,usageplan_name: str):
				"""Get Id of a usage plan specified by name.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usageplan_name (str): Name of specified usageplan.
				Returns:
					str: id
				"""
				usageplan_list = AWS.APIGateway.UsagePlan.List(apig)

				usageplan_id = ''
				for usp in usageplan_list:
					if usp['name'] == usageplan_name:
						usageplan_id = usp['id']
				return usageplan_id

			def List_Keys(apig,usageplan_name: str):
				"""List all usage plan keys.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usageplan_name (str): Name of specified usageplan.
				Returns:
					dict: server_response
				"""
				usage_plan_id = AWS.APIGateway.UsagePlan.GetId(apig,usageplan_name)
				return apig.client.get_usage_plan_keys(usagePlanId=usage_plan_id)

			def Usage(apig,usageplan_name: str,start: str,end: str):
				"""Gets the usage data of a usage plan in a specified time interval.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usageplan_name (str): Name of specified usageplan.
					start (str): '2016-01-01'
					end (str): '2016-12-31'
				Returns:
					list: usage
				Notes:
					Only past 90 days.
				"""
				usageplan_id = AWS.APIGateway.UsagePlan.GetId(apig,usageplan_name)
				return apig.client.get_usage(usagePlanId=usageplan_id,startDate=start,endDate=end)['items']

			def Create(apig,usage_name: str,purpose: str,overwrite=False,throttle_rate=20.0,throttle_burst=50,quota_limit=1000,quota_period='DAY',quota_offset=0):
				"""Create a Usage Plan with throttle and quota limits.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usage_name (str):
					purpose (str):
					overwrite (bool): True if to overwrite if usage plan already exists.
					throttle_rate (float): The steady-state rate limit.
					throttle_burst (int): The maximum rate limit over a time ranging from one to a few seconds.
					quota_limit (int): The maximum number of requests that can be made in a given time period.
					quota_period (str): 'DAY'|'WEEK'|'MONTH'; The time period in which the limit applies.
					quota_offset (int): The number of requests subtracted from the given limit in the initial time period.
				Returns:
					dict: server response to creation OR None if already an active usage plan.
				Note:
					If overwrite is True, will overwrite an existing usage plan. If not, then will return the information of that usage plan.
				"""

				#check if usage plan exists
				usage_plan_list = AWS.APIGateway.UsagePlan.List(apig)
				active_usages = [x for x in usage_plan_list if x['name'] == usage_name]

				if len(active_usages) <= 0: #doesnt exist yet
					throttle = {
						'burstLimit': throttle_burst,
						'rateLimit': throttle_rate
						}
					quota = {
						'limit': quota_limit,
						'offset': quota_offset,
						'period': quota_period
					}
					return apig.client.create_usage_plan(name=usage_name,description=purpose,throttle=throttle,quota=quota)
				else:
					if overwrite:
						return AWS.APIGateway.UsagePlan.Update(apig,active_usages[0]['id'],purpose,throttle_rate,throttle_burst,quota_limit,quota_period,quota_offset)
					else:
						return active_usages[0]

			def Update(apig,usageplan_id: str,purpose: str,throttle_rate: float,throttle_burst: int,quota_limit: int,quota_period: str,quota_offset: int):
				"""Update an existing usage plan.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usage_name (str):
					purpose (str):
					throttle_rate (float): The steady-state rate limit.
					throttle_burst (int): The maximum rate limit over a time ranging from one to a few seconds.
					quota_limit (int): The maximum number of requests that can be made in a given time period.
					quota_period (str): 'DAY'|'WEEK'|'MONTH'; The time period in which the limit applies.
					quota_offset (int): The number of requests subtracted from the given limit in the initial time period.
				Returns:
					dict: response from server.
				Ref:
					https://docs.aws.amazon.com/apigateway/api-reference/link-relation/usageplan-update/
				"""
					
				response = apig.client.update_usage_plan(
					usagePlanId=usageplan_id,
					patchOperations=[
						{
							'op': 'replace',
							'path': '/description',
							'value': purpose,
						},
						{
							'op': 'replace',
							'path': '/throttle/burstLimit',
							'value': str(throttle_burst),
						},
						{
							'op': 'replace',
							'path': '/throttle/rateLimit',
							'value': str(throttle_rate),
						},
						{
							'op': 'replace',
							'path': '/quota/limit',
							'value': str(quota_limit),
						},
						{
							'op': 'replace',
							'path': '/quota/offset',
							'value': str(quota_offset),
						},
						{
							'op': 'replace',
							'path': '/quota/period',
							'value': str(quota_period),
						},
					]
				)
				return response

			def Delete(apig,usageplan_name: str):
				"""Delete a Usage Plan.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usageplan_name (str): Specified usageplan by name.
				Returns:
					dict: server response.
				"""
				usageplan_id = AWS.APIGateway.UsagePlan.GetId(apig,usageplan_name)
				return apig.client.delete_usage_plan(usagePlanId=usageplan_id)

			def Add_Key(apig,usageplan_id: str,key_id: str,key_type='API_KEY'):
				"""Add an existing API Key to a Usage Plan.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usageplan_id (str): Id of specified usageplan.
					key_id (str): Id of specified key.
					key_type (str): 'API_KEY' | ??
				Returns:
					dict: response from server.
				"""

				try:
					return apig.client.create_usage_plan_key(usagePlanId=usageplan_id,keyId=key_id,keyType=key_type)
				except Exception as ex:

					#TODO: try to add the key,
					#can cause exception is key is already subscribed to a/this usage plan

					if ex.response['Error']['Code'] == 'ConflictException':
						keys = [x for x in apig.client.get_usage_plan_keys(usagePlanId=usageplan_id)['items'] if x['id'] == key_id]

						if len(keys) <= 0:
							raise ex #unknown conflict?

						return keys[0] #this returns the key dict, different than response?
					else:
						raise ex


					a = 5

			def Remove_Key(apig,usageplan_id: str,key_id: str):
				"""Remove an existing API Key from a Usage Plan.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					usageplan_id (str): Id of specified usageplan.
					key_id (stR): Id of specified key.
				Returns:
					dict: response from server.
				"""
				return apig.client.delete_usage_plan_key(usagePlanId=usageplan_id,keyId=key_id)

			def Add_Stage(apig,usageplan_id: str,rest_api_id:str,stage_name:str):
				"""Add a usageplan to a deployment.
				Args:
					usageplan_id (str): Id of specified usageplan.
					rest_api_id (str): Id of specified API.
					stage_name (str): Name of the deployment stage.
				Returns:
					dict: response
				Ref:
					https://github.com/boto/boto3/issues/825#issuecomment-251234288
					https://stackoverflow.com/questions/39523225/update-aws-lambda-api-key-usage-plans-with-boto3
					https://docs.aws.amazon.com/apigateway/api-reference/link-relation/usageplan-update/
				"""

				#TODO: first check if usage plan already has this stage in it?
				all_plans = AWS.APIGateway.UsagePlan.List(apig)

				this_plan = [x for x in all_plans if x['id'] == usageplan_id][0] #index will fail if plan not already created

				stages_in_this_plan = [x for x in this_plan['apiStages'] if x['stage'] == stage_name]

				if len(stages_in_this_plan) <= 0:

					return apig.client.update_usage_plan(
						usagePlanId=usageplan_id,
						patchOperations=[
							{
								'op': 'add',#|'remove'|'replace'|'move'|'copy'|'test',
								'path': '/apiStages',
								'value': rest_api_id + ':' + stage_name
							}
						])

				return this_plan

		class Key:
			"""Rest API Authorization Keys.
			"""
			def List(apig):
				"""List all API Keys.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
				Returns:
					list: keys.
				"""
				return apig.client.get_api_keys()['items']

			def Get_Key(apig,key_id: str,include_value=False):
				"""Get the API key specified, will return value if to include_value.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					key_id (str): Key Id.
					include_value (bool): True to include the value in the response from server.
				Returns:
					dict: response from server.
				"""
				return apig.client.get_api_key(apiKey=key_id,includeValue=include_value)

			def Create(apig,key_name: str,purpose: str,enabled=True,value='',generate_distict_id=True):
				"""Create an API key.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					key_name (str): Name of the key.
					purpose (str): Why the key was needed.
					enabled (bool): True if can be used by callers.
					value (str): Specified value of the key. TODO: if empty, auto gens?
					generate_distinct_id (bool): True to make the key identifier distinct from the created api key value.
				Returns:
					dict: server response OR already created api key.
				"""

				api_key_list = AWS.APIGateway.Key.List(apig)

				active_api_keys = [x for x in api_key_list if x['name'] == key_name]

				if len(active_api_keys) <= 0:
					return apig.client.create_api_key(name=key_name,description=purpose,\
									   enabled=enabled,generateDistinctId=generate_distict_id,value=value)
				else:
					return AWS.APIGateway.Key.Get_Key(apig,active_api_keys[0]['id'],include_value=True)

			def Delete(apig,key_id: str):
				"""Delete an API key.
				Args:
					apig (APIGateway): Instantiated APIGateway credential access object.
					key_id (str): Id of key to delete.
				Returns:
					dict: server response.
				"""
				return apig.client.delete_api_key(apiKey=key_id)

	class Lambda:
		"""Class for managing Lambda functions.
		Args:
			aws_creds (dict):
		"""

		image = 'quiltdata/lambda' #'dacut/amazon-linux-python-3.6' no longer available

		def __init__(self,aws_creds):

			#configure the seesion via credentials
			self.session = boto3.Session(
				aws_access_key_id = aws_creds['aws_access_key_id'],
				aws_secret_access_key = aws_creds['aws_secret_access_key']
			)
				
			self.client = self.session.client('lambda',region_name=aws_creds['region'])

			return super().__init__()

		def Summary(self):
			"""Get account detail summary.
			Returns:
				dict: https://docs.aws.amazon.com/lambda/latest/dg/API_AccountLimit.html
			TODO: https://docs.aws.amazon.com/lambda/latest/dg/concurrent-executions.html"""
			return self.client.get_account_settings()

		def List(self,marker=None,max_items=100,function_version='ALL'):
			"""List all the Lambda Functions in the region.
			Args:
				
			Returns:
				list: Lambda functions as dicts.
			"""
			if marker is not None:
				return self.client.list_functions(
					FunctionVersion=function_version,
					Marker=marker,
					MaxItems=max_items)['Functions']
			else:
				return self.client.list_functions(
					FunctionVersion=function_version,
					MaxItems=max_items)['Functions']

		def Create(self,fcn_name: str,purpose: str,runtime: str,fcn_Filepath: str,dependancy_zip_filePath: str,role_arn:str,sup_Filepaths_list=[],fcn_handler='lambda_handler',mem=128,timeout=10,overwrite=False):
			"""Create/update a Lambda Function
			Args:
				fcn_name (str): Name of function to create.
				purpose (str): Why create this function.
				runtime (str): 'nodejs'|'nodejs4.3'|'nodejs6.10'|'nodejs8.10'|'java8'|'python2.7'|
					'python3.6'|'dotnetcore1.0'|'dotnetcore2.0'|'dotnetcore2.1'|'nodejs4.3-edge'|'go1.x'
				fcn_Filepath (str): Local filepath to function file.
				dependancy_zip_filePath (str): Local filepath to depedancies in zip file.
				role_arn (str): The IAM role arn to assume.
				sup_Filepaths_list (list): List of supplimentary files to include.
				fcn_handler (str): Name of function inside function file that handles invocation.
				mem (int): Function memory allowcation in MB, will be rounded up to nearest x64.
				timeout (int): Function timeout in seconds.
				overwrite (bool): True to update the lambda function if it already exists.
			Returns:
				list: List of server responses.
			"""

			#round to nearest 64bytes
			mem = (int(mem/64)+int(mem%64 > 0)) * 64

			#add the function file into the dependancy zip
			zip = zipfile.ZipFile(dependancy_zip_filePath,'a')
			zip.write(fcn_Filepath, os.path.basename(fcn_Filepath))

			#add supplimentary files
			if len(sup_Filepaths_list) > 0:
				for sup_Filepath in sup_Filepaths_list:
					zip.write(sup_Filepath, os.path.basename(sup_Filepath))
			zip.close()

			#read the zipped code file
			with open(dependancy_zip_filePath, 'rb') as f:
				zipped_code = f.read()

			#get list of lambda functions
			lambda_function_list = self.List()
			lambda_fcn = next((x for x in lambda_function_list if x['FunctionName'] == fcn_name), None)

			#if exist, only upload if overwrite
			if (lambda_fcn is not None) and (overwrite):

				response1 = self.client.update_function_code(
					FunctionName = fcn_name,
					ZipFile = zipped_code)

				response2 = self.client.update_function_configuration(
					FunctionName = fcn_name,
					Role = role_arn,
					Handler = os.path.basename(fcn_Filepath)[:-3] + '.' + fcn_handler,
					Description = purpose,
					Timeout = timeout,
					MemorySize = mem,
					)
				response = [response1, response2]
			else:
				response = [self.client.create_function(
					FunctionName = fcn_name,
					Runtime = runtime,
					Role = role_arn,
					Handler = os.path.basename(fcn_Filepath)[:-3] + '.' + fcn_handler,
					Code = {
						'ZipFile':  zipped_code
						},
					Description = purpose,
					Timeout = timeout,
					MemorySize = mem,
					#Publish=True|False,
					)]
			return response

		def Add_Permission(self,fcn_name: str,source_arn: str,action='lambda:InvokeFunction',principle='apigateway.amazonaws.com',statementID=uuid.uuid4().hex):
			"""Add permission for a lambda function to access another resource by arn.
			Args:
				fcn_name (str): Specified lambda function by name.
				source_arn (str): ARN of the source to permit access to.
				action (str): lambda:InvokeFunction | lambda:GetFunction |   -> lambda:*   ?
				principle (str): domain style for services-> s3.amazonaws.com | sns.amazonaws.com | apigateway.amazonaws.com
				statemendID (str): A statement identifier that differentiates the statement from others in the same policy.
			Returns:
				dict: server response.
			Ref:
				https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda.html#Lambda.Client.add_permission
				https://forums.aws.amazon.com/thread.jspa?messageID=745586&#745586
				https://docs.aws.amazon.com/lambda/latest/dg/with-on-demand-https-example.html
			Notes:
				--source-arn arn:aws:execute-api:<region>:<account_id>:<api_id>/<stage_name>/*
				The wildcard at the end is because, perhaps, both the http_method and CORs OPTION must have permission
			"""
			
			resp = self.client.add_permission(
				FunctionName=fcn_name,
				StatementId=statementID,
				Action=action,
				Principal=principle,
				SourceArn=source_arn)

			return resp

		def Invoke(self,fcn_name: str,event: dict):
			"""Invoke a serverless fcn by name, and provide the event of arguments.
			Args:
				fcn_name (str): Function specified by name.
				event (dict): Json dict of event params.
			Returns:
				dict: function response.
			"""
				
			response = self.client.invoke(
				FunctionName=fcn_name,
				InvocationType='RequestResponse',
				Payload=json.dumps(event),
				)

			return json.loads(response['Payload'].read())

	class WorkMail:
			
		#https://docs.aws.amazon.com/workmail/latest/adminguide/manage-mailboxes.html
		#from messaging import Email
		#Email.smtp_ssl_host = 'smtp.mail.us-east-1.awsapps.com'
		#Email.smtp_ssl_port = 465
		#Email.Send('phil@zeural.com','userpassword','support@zeural.com',['pmp47@case.edu'],'test123','testing python emails')
		def __init__(self,kwargs):

			#configure the seesion via credentials
			self.session = boto3.Session(
				aws_access_key_id = kwargs['aws_access_key_id'],
				aws_secret_access_key = kwargs['aws_secret_access_key']
			)
				
			self.client = self.session.client('workmail',region_name=kwargs['region'])

			return super().__init__()

		class Organizations:
				
			def List(wm):
				"""List Workmail Organizations.
				Different from AWS.Organizations?"""

				response = wm.client.list_organizations(
					#NextToken='string',
					#MaxResults=123
					)

				return response['OrganizationSummaries']

			def GetId(wm,org_name: str):
				"""Get Id of Organization specified by name.
				Args:
					org_name (str): Name of specified organization.
				Returns:
					str: org_id"""
				orgs = AWS.WorkMail.Organizations.List(wm)
				for org in orgs:
					if org['Alias'] == org_name:
						return org['OrganizationId']
				return None

		class Resource:

			def Create(wm,org_id,name,resource_type):

				#resource_type = 'ROOM'|'EQUIPMENT'

				response = wm.client.create_resource(OrganizationId=org_id,Name=name,Type=resource_type)
					
				return response

		class Users:

			def List(wm,org_name: str):
				"""List users in an organization.
				Args:
					org_name (stR): Organization specified by name.
				Returns:
					list: list of users as dicts."""
				org_id = AWS.WorkMail.Organizations.GetId(wm,org_name)

				return wm.client.list_users(
					OrganizationId=org_id,
					#NextToken='string',
					#MaxResults=123
				)['Users']

			def GetId(wm, username: str, org_name: str):
				"""Get Id of User specified by name.
				Args:
					username (str): Name of user.
					org_name (str): Name of specified organization.
				Returns:
					str: user_id"""
				users = AWS.WorkMail.Users.List(wm,org_name)
				for user in users:
					if user['Name'] == username:
						return org['UserId']
				return None

			def Create(wm,username: str,user_displayname: str,org_name: str,password: str):
				"""Create a User who can be registered.
				Args:
					username (str): Name of user.
					user_displayname (str): Email display name of user.
					org_name (str): Name of organization to add user to.
					password (str): User's password for logging in.
				Returns:
					dict: server response."""
				org_id = AWS.WorkMail.Organizations.GetId(wm,org_name)
				return wm.client.create_user(
					OrganizationId=org_id,
					Name=username,
					DisplayName=user_displayname,
					Password=password)

			def Delete(wm,username: str,org_name: str):
				"""Delete a User.
				Args:
					username (str): Name of user.
					org_name (str): Name of organization to add user to.
				Returns:
					dict: server response."""
				org_id = AWS.WorkMail.Organizations.GetId(wm,org_name)
				user_id = AWS.WorkMail.Users.GetId(wm,username,org_name)
				return wm.client.delete_user(
					OrganizationId=org_id,
					UserId=user_id)

			def Disable():
				pass

	class IAM:
		"""For managing IAM.
		Ref: 
			http://boto3.readthedocs.io/en/latest/reference/services/iam.html
		"""

		def __init__(self,kwargs):

			#configure the seesion via credentials
			try:
				self.resource = boto3.resource('iam',
					aws_access_key_id = kwargs['aws_access_key_id'],
					aws_secret_access_key = kwargs['aws_secret_access_key'])
			except:
				self.resource = boto3.resource('iam')

			return super().__init__()

		def Summary(iam,filter=['User','Role','Group','LocalManagedPolicy','AWSManagedPolicy'],marker=None,maxitems=100):
			"""Retrieves information abou t all IAM users, groups, roles, and policies in your AWS account, including their relationships to one another.
			Args:
				iam (AWS.IAM): Instantiated credential object.
				filter (list): Types of IAM objects to filter for.
				marker (?): Pagination
				maxiitems (int): Maximum number of items to be returned.
			Returns:
				dict: server_response
			"""

			if marker is None:
				response = iam.resource.meta.client.get_account_authorization_details(
					Filter=filter,
					MaxItems=maxitems)
			else:
				response = iam.resource.meta.client.get_account_authorization_details(
					Filter=filter,
					Marker=marker,
					MaxItems=maxitems)

			return response

		class User:
			"""Sub class for managing IAM Users.
			TODO: 
				add in MFA and password policy
			"""

			def List(iam,tag='/',marker=None,maxitems=100):
				"""List all users.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					tag (str): Custom tag to help group/identify.
					marker (?):
					maxitems (int):
				Returns:
					dict: response
				"""

				tag = AWS.preptag(tag)
				if marker is None:
					response = iam.resource.meta.client.list_users(
						PathPrefix=tag,
						MaxItems=maxitems)
				else:
					response = iam.resource.meta.client.list_users(
						PathPrefix=tag,
						Marker=marker,
						MaxItems=maxitems)

				return response

			def Create(iam,username: str,tag='/'):
				"""Create an IAM User.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
					tag (str): Custom tag to help group/identify.
				Returns:
					iam.User: ??? aws boto3 obj?
				TODO: 
					PermissionsBoundary
				"""
				return iam.resource.User(username).create(Path=AWS.preptag(tag))

			def Delete(iam,username: str):
				"""Delete an IAM User.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
				Returns:
					dict: response
				"""
				return iam.resource.User(username).delete()

			def List_AccessKeys(iam,username: str,marker=None,maxitems=100):
				"""Returns information about the access key IDs associated with the specified IAM user.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
				Returns:
					list: access_keys
				"""
				return list(iam.resource.User(username).access_keys.all())

			def AccessKey_LastUse(iam,username: str,key_index=0):
				"""Retrieves information about when the specified access key was last used.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
					key_index (int): Index of access_key within User's list.
				Returns:
					
				"""

				accesskeyid = AWS.IAM.User.List_AccessKeys(iam,username)[key_index].id
				return iam.resource.meta.client.get_access_key_last_used(AccessKeyId=accesskeyid)['AccessKeyLastUsed']
				
			def Generate_AccessKey(iam,username: str):
				"""Creates a new AWS secret access key and corresponding AWS access key ID for the specified user. 
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
				Returns:
					dict: response
				Notes:
					The default status for new keys is Active. 
					If a user name is not specified, IAM determines the 	user name implicitly based on the AWS access key ID signing the request.
					Because this operation 	works for access keys under the AWS account, you can use this operation to manage AWS account root user credentials.
				"""
				return iam.resource.meta.client.create_access_key(UserName=username)

			def Update_AccessKey(iam,username: str,status: str,key_ind=0):
				"""Changes the status of the specified access key from Active to Inactive.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
					status (str): 'Active'|'Inactive'
					key_ind (int): Index of key to update when listed for user.
				Returns:
					dict: response
				Notes:
					This operation can be used to disable a user's key as part of a key rotation workflow.
				"""
				accesskeyid = AWS.IAM.User.List_AccessKeys(iam,username)[key_ind].id
				return iam.resource.meta.client.update_access_key(UserName=username,AccessKeyId=accesskeyid,Status=status)

			def Delete_AccessKey(iam,username: str,key_ind=0):
				"""Deletes the access key pair associated with the specified IAM user.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					username (str):
					key_ind (int): Index of key to update when listed for user.
				Returns:
					dict: response
				Notes:
					If a user name is not specified, IAM determines the 	user name implicitly based on the AWS access key ID signing the request.
					Because this operation 	works for access keys under the AWS account, you can use this operation to manage AWS account root user credentials.
				"""
				accesskeyid = AWS.IAM.User.List_AccessKeys(iam,username)[key_ind].id
				return iam.resource.meta.client.delete_access_key(UserName=username,AccessKeyId=accesskeyid)

		class Group:
			"""Sub class for managing IAM Groups.
			"""

			def List(iam,tag='/',marker=None,maxitems=100):
				"""List all groups.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					tag (str): Custom tag to help group/identify.
					marker (?):
					maxitems (int):
				Returns:
					dict: response
				"""

				tag = AWS.preptag(tag)
				if marker is None:
					response = iam.resource.meta.client.list_groups(
						PathPrefix=tag,
						MaxItems=maxitems)
				else:
					response = iam.resource.meta.client.list_groups(
						PathPrefix=tag,
						Marker=marker,
						MaxItems=maxitems)

				return response

			def Create(iam,groupname: str,tag='/'):
				"""Create an IAM Group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
					tag (str): Custom tag to help group/identify.
				Returns:
					iam.Group: boto3 obj
				"""
				return iam.resource.Group(groupname).create(Path=AWS.preptag(tag))
				
			def Delete(iam,groupname: str):
				"""Delete an IAM Group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
				Returns:
					dict: response
				"""
				return iam.resource.Group(groupname).delete()
				
			def Add_User(iam,groupname: str,username: str):
				"""Assign an IAM User to an IAM Group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
					username (str):
				Returns:
					dict: response
				"""
				return iam.resource.Group(groupname).add_user(UserName=username)

			def Remove_User(iam,groupname: str,username: str):
				"""Remove an IAM User from an IAM Group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
					username (str):
				Returns:
					dict: response
				"""
				return iam.resource.Group(groupname).remove_user(UserName=username)

			def List_Policies(iam,groupname: str):
				"""List all policies in a group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
				Returns:
					list:
				TODO: 
					must include '/tag/' in groupname?
				"""

				return list(iam.resource.Group(groupname).policies.all())

			def List_Attached_Policies(iam,groupname: str,tag='/'):
				"""List all policies attached to a group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
					tag (str):
				Returns:
					list:
				"""
				return list(iam.resource.Group(groupname).attached_policies.filter(PathPrefix=AWS.preptag(tag)))

			def Attach_Policy(iam,groupname: str,policyname: str,tag='/',scope='Local'):
				"""Add an IAM Policy to an IAM Group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
					policyname (str):
					tag (str):
					scope (str):
				Returns:
					
				"""

				custom_policies = AWS.IAM.Policy.List(iam,scope=scope)
				policy_arn = ''
				tag = AWS.preptag(tag)
				for policy in custom_policies:
					if (policy['Path'] == tag) & (policy['PolicyName'] == policyname):
						policy_arn = policy['Arn']

				return iam.resource.Group(groupname).attach_policy(PolicyArn=policy_arn)
					
			def Remove_Policy(iam,groupname: str,policyname: str,tag='/',scope='Local'):
				"""Remove an IAM Policy from an IAM Group.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					groupname (str):
					policyname (str):
					tag (str):
					scope (str):
				Returns:
					
				"""

				custom_policies = AWS.IAM.Policy.List(iam,scope=scope)
				policy_arn = ''
				tag = AWS.preptag(tag)
				for policy in custom_policies:
					if (policy['Path'] == tag) & (policy['PolicyName'] == policyname):
						policy_arn = policy['Arn']

				return iam.resource.Group(groupname).detach_policy(PolicyArn=policy_arn)

		class Policy:
			"""Sub class for managing IAM Policies.
			TODO: 
				Simulate -> https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.simulate_custom_policy
			"""

			def List(iam,scope='All',onlyattached=False,tag='/',usagefilter='PermissionsPolicy',marker=None,maxitems=100):
				"""List all available policies.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					scope (str): 'All'|'AWS'|'Local'
					onlyattached (bool):
					tag (str):
					usagefilter (str): 'PermissionsPolicy'|'PermissionsBoundary'
					marker (?): 
					maxitems (int):
				Returns:
					dict: response
				"""
					
				tag = AWS.preptag(tag)
				if marker is None:
					response = iam.resource.meta.client.list_policies(
						Scope=scope,
						OnlyAttached=onlyattached,
						PathPrefix=tag,
						PolicyUsageFilter=usagefilter,
						MaxItems=maxitems)
				else:
					response = iam.resource.meta.client.list_policies(
						Scope=scope,
						OnlyAttached=onlyattached,
						PathPrefix=tag,
						PolicyUsageFilter=usagefilter,
						Marker=marker,
						MaxItems=maxitems)

				return response
				
			def Statementize(service: str,actions: list,effect: str,resources: list):
				"""For creating a policy statement.
				Args:
					service (str): aws service id like 's3' or 'lambda' or 'dynamodb'
					action (list): list of strings -> ['PutObject','GetObject','*']
					effect (str): 'Allow'|'Deny'
					resources (list): list of resource strings -> ['mybucket1/*','mybucket2','*']
				Returns:
					dict: policy_statement
				"""
				#properly prefix resources and actions
				arnprefix = 'arn:aws:'

				for r in range(len(resources)):
					resources[r] = arnprefix + service + ':::' + resources[r]

				for a in range(len(actions)):
					actions[a] = service + ':' + actions[a]

				return {
					'Action':actions,
					'Effect':effect,
					'Resource':resources
					}

			def Create(iam,name: str,purpose: str,statements: list,tag='/',version='2012-10-17'):
				"""Creates an IAM Policy.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					name (str): 'identifier' of the policy
					purpose (str): 'Meaningful description of the purpose of the policy'
					statements: list; [statement1,statement2,...]; use Statementize
					tag (str):
					version (str):
				Returns:
					dict: server_response
				"""

				if len(statements) <= 0: raise ValueError('Must provide atleast 1 valid policy statement')

				tag = AWS.preptag(tag)

				#build policy document
				policyDoc = {
					'Statement': statements,
					'Version': version
					}

				#transform policy document into json
				jsonPolicyDocument = json.dumps(policyDoc)

				#use client to submit
				response = iam.resource.meta.client.create_policy(
					PolicyName=name,
					Path=tag,
					PolicyDocument=jsonPolicyDocument,
					Description=purpose
					)

				return response

			def Delete(iam,name: str,tag='/',scope='Local'):
				"""Deletes an IAM Policy.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					name (str): 'identifier' of the policy
					tag (str): Custom tag to help group/identify.
					scope (str): 'All'|'AWS'|'Local'
				Returns:
					dict: response
				"""
					
				custom_policies = AWS.IAM.Policy.List(iam,scope=scope)['Policies']
				policy_arn = ''
				tag = AWS.preptag(tag)
				for policy in custom_policies:
					if (policy['Path'] == tag) & (policy['PolicyName'] == name):
						policy_arn = policy['Arn']

				if policy_arn == '': raise ValueError('Specified policy not found to exist.')

				return iam.resource.meta.client.delete_policy(PolicyArn=policy_arn)

		class Role:
			"""Sub class for managing IAM Roles.
			TODO: 
				update,manage access keys
			"""

			def List(iam,tag='/',marker=None,maxitems=100):
				"""List all Roles.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					tag (str):
				Returns:
					dict: response
				"""

				tag = AWS.preptag(tag)
				if marker is None:
					response = iam.resource.meta.client.list_roles(
						PathPrefix=tag,
						MaxItems=maxitems
					)
				else:
					response = iam.resource.meta.client.list_roles(
						PathPrefix=tag,
						Marker=marker,
						MaxItems=maxitems
					)
				return response

			def Create(iam,name: str,purpose: str,service: str,tag='/',max_session_duration_s=3600,version='2012-10-17'):
				"""Create an IAM Role.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					name (str):
					purpose (str):
					service (str): 'lambda' or 'ec2'
					tag (str):
					max_session_duration_s (int):
					version (str):
				Returns:
					dict : response
				"""
					
				#create the service role assumption (what service can use this)
				#TODO: allow users: "Principal": { "AWS": "arn:aws:iam::AWS-account-ID:user/user-name" }
				assume_role_policy_document = json.dumps({
					'Version': version,
					'Statement': [
						{
							'Action': 'sts:AssumeRole',
							'Principal': {
								'Service': service + '.amazonaws.com'
							}, 
							'Effect': 'Allow',
							'Sid': ''
						}
					]
				})

				#TODO: permissions_boundary
				return iam.resource.meta.client.create_role(Path=AWS.preptag(tag),RoleName=name,\
					AssumeRolePolicyDocument=assume_role_policy_document,Description=purpose,\
					MaxSessionDuration=max_session_duration_s)

			def Delete(iam,name: str):
				"""Delete an IAM specified by name.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					name (str):
				Returns:
				"""
				return iam.resource.meta.client.delete_role(RoleName=name)

			def Attach_Policy(iam,rolename: str,policyname: str,tag='/',scope='Local'):
				"""Attach a Policy specified by ARN to an IAM Role.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					rolename (str):
					policyname (str):
					tag (str): Custom tag to help group/identify.
					scope (str):
				Returns:
					
				"""
					
				custom_policies = AWS.IAM.Policy.List(iam,scope=scope)
				policy_arn = ''
				tag = AWS.preptag(tag)
				for policy in custom_policies:
					if (policy['Path'] == tag) & (policy['PolicyName'] == policyname):
						policy_arn = policy['Arn']

				return iam.resource.meta.client.attach_role_policy(RoleName=rolename,PolicyArn=policy_arn)

			def Remove_Policy(iam,rolename: str,policyname: str,tag='/',scope='Local'):
				"""Detach an IAM Policy from an IAM Role.
				Args:
					iam (AWS.IAM): Instantiated credential object.
					rolename (str):
					policyname (str):
					tag (str): Custom tag to help group/identify.
					scope (str):
				Returns:

				"""

				custom_policies = AWS.IAM.Policy.List(iam,scope=scope)
				policy_arn = ''
				tag = AWS.preptag(tag)
				for policy in custom_policies:
					if (policy['Path'] == tag) & (policy['PolicyName'] == policyname):
						policy_arn = policy['Arn']

				return iam.resource.meta.client.detach_role_policy(RoleName=rolename,PolicyArn=policy_arn)

	class Route53:

		def __init__(self,kwargs):

			#configure the seesion via credentials
			self.session = boto3.Session(
				aws_access_key_id = kwargs['aws_access_key_id'],
				aws_secret_access_key = kwargs['aws_secret_access_key']
			)
				
			self.client = self.session.client('route53',region_name=kwargs['region'])

			return super().__init__()

	class Organizations:

		def __init__(self,kwargs):

			#configure the seesion via credentials
			self.session = boto3.Session(
				aws_access_key_id = kwargs['aws_access_key_id'],
				aws_secret_access_key = kwargs['aws_secret_access_key']
			)
				
			self.client = self.session.client('organizations',region_name=kwargs['region'])

			return super().__init__()


		def Describe(org):
			"""Describe the organization user is a part of."""
			response = org.client.describe_organization()

			return response['Organization']

		def Create(org,billingType='CONSOLIDATED_BILLING'):
			"""Create an organization."""

			response = org.client.create_organization(FeatureSet=billingType)

			return response

		class Accounts:

			def List(org):

				response = org.client.list_accounts()

				return response

	class S3:
		#TODO: WASABI USES s3 so jsut inhereit and change endpoint
		def __init__(self,kwargs,isLocalTest: bool):

			#configure the resource via credentials
			try:
				#configure the seesion via credentials
				self.session = boto3.Session(
					aws_access_key_id = kwargs['aws_access_key_id'],
					aws_secret_access_key = kwargs['aws_secret_access_key']
				)
				
				self.client = self.session.client('s3',region_name=kwargs['region'])
				self.region = kwargs['region']
			except:
				#for if a service using a role, creds wont be specified
				self.client = boto3.resource('s3').meta.client

			return super().__init__()

	class WebAppFirewall:

		def __init__(self,kwargs,isLocalTest: bool):

			#configure the resource via credentials
			try:
				#configure the seesion via credentials
				self.session = boto3.Session(
					aws_access_key_id = kwargs['aws_access_key_id'],
					aws_secret_access_key = kwargs['aws_secret_access_key']
				)
				
				self.client = self.session.client('waf',region_name=kwargs['region'])
				self.region = kwargs['region']
			except:
				#for if a service using a role, creds wont be specified
				self.client = boto3.resource('waf').meta.client

			return super().__init__()