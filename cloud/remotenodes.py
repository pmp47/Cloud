#--start requirements--
#pip installs
from paramiko import SSHClient, RSAKey, AutoAddPolicy
from security import Encrypting, Hashing

#customs
from dictableobj import UniqueStatusObject, DictableObj

#builtins
import copy
import json
import io
import subprocess

#--end requirements--

class Communication:
	"""Communication with remote nodes.
	Attributes:
		key (RSAKey): Private PEM RSA Key.
		ip_address (str): IPv4 address of node.
		username (str): Username to log in as.
		sshclient (SSHClient): SSH client used to securely connect to node.
	Notes:
		Must .Connect() before .ExcuteCommand() or .PutFile() and .Close() after.
	Ref:
		https://parallel-ssh.org/post/ssh2-python/
	"""

	def __init__(self,kwargs):

		self.key = RSAKey.from_private_key(io.StringIO(kwargs['asymKeys']['private']))
		self.ip_address = kwargs['ip_address']
		self.username = kwargs['username']
			
		self.sshclient = SSHClient()
		self.sshclient.set_missing_host_key_policy(AutoAddPolicy())

		return super().__init__()

	def Connect(self,port=22,timeout=10):
		"""Open an SSH connection.
		Args:
			port (int): Network port to connect to.
			timeout (int): Time to close connections if no response in seconds.
		"""
		#SSH connect
		self.sshclient.connect(self.ip_address,port=port,username=self.username,pkey=self.key,timeout=timeout)
		return self

	def Close(self):
		"""Close an SSH connection.
		"""
		self.sshclient.close()
		return self

	def ExecuteCommand(self,command: str,waitForResponse=True):#,listen=True):
		"""Execute a command on the node from a remote location.
		Arg:
			command (str): Command to execute.
			waitForResponse (bool): True to wait for response to command from node.
		Returns:
			list: lines returned in stdout response.
			list: lines returned in stderr response.
		"""
		
		#submit command
		stdin, stdout, stderr = self.sshclient.exec_command(command)

		if waitForResponse:
			#wait for response recieved
			stdout.channel.recv_exit_status()
			
			#read the response
			lines = stdout.readlines()

			errlines = stderr.readlines()

			return lines, errlines
		else:
			#if listen:
			#	a = 5
				#stdin.close()
				#for line in iter(lambda: stdout.readline(2048), ""):
				#	print(line, end="")
			return [], []

	def PutFile(self,local_filePath: str,remote_filePath: str):
		"""Put a local file to a remote node using SFTP.
		Args:
			local_filePath (str): Filepath of local file to copy.
			remote_filePath (str): Filepath on remote node to copy file to.
		"""
		
		sftp = self.sshclient.open_sftp()
		sftp.put(local_filePath,remote_filePath)
		sftp.close()
		return self

	def GetFile(self,local_filePath: str,remote_filePath: str):
		"""Get a file from a remote node using SFTP.
		Args:
			local_filePath (str): Filepath of local file to copy to.
			remote_filePath (str): Filepath on remote node to copy file from.
		"""
		sftp = self.sshclient.open_sftp()
		sftp.get(remote_filePath,local_filePath)
		sftp.close()
		return self

class ComputeTask(UniqueStatusObject):
	"""A computing task for a remote node.
	Attributes:
		status (int):
		ID (str):
		username (str): Name of User who created the compute task.
		command (str): Command to begin the task.
		func_filepath (str): For when specifying a function file as the task source.
		created (??)
		started (??)
		finished (??)
		ttl (??)
		notes
		params_dict (dict):

		"""
	status_removed = -1
	status_complete = 0
	status_available = 1
	status_checkedout = 2
	status_exception = 3

	keys = {
		'hash': ['status','N'],
		'range': ['username','S'],
		'sort': ['command','S'],
		'priori': ['ID','S']
		}

	#mnemonic_key = 'priori' #which key is the heuristic key unnec?

	def __init__(self,kwargs):

		self.username = kwargs['username']
		self.command = kwargs['command']
		self.created = kwargs['created']

		try:
			self.func_filepath = kwargs['func_filepath']
		except:
			self.func_filepath = None
		
		try:
			self.params_dict = kwargs['params_dict']
		except:
			self.params_dict = None

		try:
			self.ttl = kwargs['ttl']
		except:
			self.ttl = None

		try:
			#task indication
			self.status = kwargs['status']

			#worker signage
			self.started = kwargs['started']
			self.finished = kwargs['finished']

			self.notes = kwargs['notes']
		except:
			#task indication

			#worker signage
			self.started = None
			self.finished = None

			self.notes = None

		return super().__init__(kwargs)

class TaskArchive(DictableObj):
	"""A compiled archive of ComputeTasks.
	Attributes:
		username (str): Who compiled this archive?
		task_list (list): List of compute_task.Dictify()
		compiledDN (??): datenum of when compiled
	"""

	def __init__(self,kwargs):

		self.username = kwargs['username']
		self.task_list = kwargs['task_list']
		self.compiledDN = kwargs['compiledDN']

		return super().__init__()

class ComputeCluster(DictableObj):
	"""A cluster of nodes to do compute work.
	Attributes:
		cluster_config (dict): 
		createdDNs (list):
		ip_addresses (list):
		hardened_nodes (list):
		
	"""
	def __init__(self,kwargs):

		#config params of cluster
		self.cluster_config = kwargs['cluster_config']
		
		#list of node ip address
		self.ip_addresses = kwargs['ip_addresses']
		
		#hardened node access
		self.hardened_nodes = kwargs['hardened_nodes']

		return super().__init__()

class HardenedNode(DictableObj):
	"""A remote node hardened by network security standards.
	Args:
		username (str):
		ssh_port (int):
		ip_address (str):
		mac_address (str):
		asymKeys (dict):
	
	"""
	def __init__(self,kwargs):

		self.username = kwargs['username']
		self.ssh_port = kwargs['ssh_port']
		self.ip_address = kwargs['ip_address']
		self.mac_address = kwargs['mac_address']
		self.asymKeys = kwargs['asymKeys']

		return super().__init__()
