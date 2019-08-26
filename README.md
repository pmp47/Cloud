
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

