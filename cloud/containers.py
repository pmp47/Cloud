#--start requirements--
#pip installs

#customs
import flashfile_template #importing as trick to auto include in package

#builtins
import subprocess
import os
from datetime import datetime
import zipfile
import sys

#--end requirements--
def tprint(content: str):
	print(str(datetime.now()) + content)

class Linux:
	"""Linux OS container class.
	TODO: 
		have static vars be for selecting distributions
		#like ubuntu vs cent os
		#to set things like using yum or apt-get
		https://www.digitalocean.com/community/tutorials/package-management-basics-apt-yum-dnf-pkg
	"""

	class API:
		
		def ListDir(dir='/'):
			return 'ls ' + dir

		def Install(apt: str,useYum=False):
			#TODO: autoYes=False
			if useYum:
				return 'yum install ' + apt
			else:
				return 'apt-get install ' + apt

		def MakeDir(dir: str,parents=False):
			if parents: dir = '-p ' + dir
			return 'mkdir ' + dir

		def Unzip(zip_filepath: str,dest_folderpath: str):
			return 'unzip ' + zip_filepath + ' -d ' + dest_folderpath

		def DeleteDir(dir: str):
			return 'rm -r ' + dir

		def ReadFile(filepath: str):
			return 'cat ' + filepath

		def WriteFile(text_lines: list,filepath: str,addNewLine=True,eFlag=False):
			"""Produce command lines for writing a file.
			Args:
				text_lines (list): 
				filepath (str):
				addNewLine (bool):
				eFlag (bool):
			Notes:
				If your text_lines contain single quotes, you must triple escape them:
				var_str = 'hello' turns into var_str = ///'hello///'
			"""
			if addNewLine:
				file_text = '\n'.join(text_lines)
			else:
				file_text = ''.join(text_lines)
			if eFlag:
				return 'echo -en \'' + file_text + '\' > ' + filepath
			else:
				return 'echo $\'' + file_text + '\' > ' + filepath #https://stackoverflow.com/questions/8467424/echo-newline-in-bash-prints-literal-n
			#return 'echo $\\\'' + file_text + '\\\' > ' + filepath #https://stackoverflow.com/questions/8467424/echo-newline-in-bash-prints-literal-n

		class Security:
			#https://www.digitalocean.com/community/tutorials/7-security-measures-to-protect-your-servers
			def AddUser(username: str):
				return 'adduser ' + username

			def AddUserToGroup(username: str,group='sudo'):
				return 'usermod -aG ' + group + ' ' + username

			def SSH_Harden(username: str,sshd_config_lines: list,new_ssh_port: int):
				"""Harden a linux instance by editing /etc/ssh_config.
				Args:
					username (str):
					sshd_config_lines (list):
					new_ssh_port (int):
				Returns:
					list: hardened_sshd_config_lines
				Ref:
					https://github.com/besnik/tutorials/tree/master/linux-hardening
					https://linux-audit.com/audit-and-harden-your-ssh-configuration/
					https://www.freebsd.org/cgi/man.cgi?sshd_config(5)
					https://help.ubuntu.com/community/StricterDefaults
				"""
				def MatchingLine(line: str,pred: str):
					ypred = pred + ' yes'
					npred = pred + ' no'
					if line[:len(pred)] == pred:
						return True
					if line[:len(ypred)] == ypred:
						return True
					if line[:len(npred)] == npred:
						return True
					if line[:len(pred)+1] == ('#' + pred):
						return True
					if line[:len(ypred)+1] == ('#' + ypred):
						return True
					if line[:len(npred)+1] == ('#' + npred):
						return True
					if pred[-1:] == '\n':
						return False
					else:
						return MatchingLine(line,pred + '\n')

				hardened_sshd_config_lines = []
				for line in sshd_config_lines:

					if MatchingLine(line,'Port 22'): #change ssh port
						line = 'Port ' + str(new_ssh_port) + '\n'
					#if MatchingLine(line,'PermitRootLogin'): #disallow login as root user
						#line = 'PermitRootLogin no\n'
					if MatchingLine(line,'PubkeyAuthentication'): #force publickey use
						line = 'PubkeyAuthentication yes\n'
					if MatchingLine(line,'PasswordAuthentication'): #disallow using passwords - force rsa keys
						line = 'PasswordAuthentication no\n'
					if MatchingLine(line,'AddressFamily'): #only lets ipv4 addresses use ssh
						line = 'AddressFamily inet\n'
					if MatchingLine(line,'X11Forwarding'): #disable gui?
						line = 'X11Forwarding no\n'
					if MatchingLine(line,'PermitEmptyPasswords'): #dont let empty passwords?
						line = 'PermitEmptyPasswords no\n'
					if MatchingLine(line,'IgnoreRhosts'): #dont use rhosts
						line = 'IgnoreRhosts yes\n'
					if MatchingLine(line,'MaxAuthTries '): #
						line = 'MaxAuthTries 3\n'
					if MatchingLine(line,'PermitEmptyPasswords'): #
						line = 'PermitEmptyPasswords no\n'
					if MatchingLine(line,'AllowUsers'): #
						line = 'AllowUsers ' + username + '\n'
					if MatchingLine(line,'Protocol'): #TODO: why - update from old protocol incase?
						line = 'Protocol 2\n'
					if MatchingLine(line,'AllowTcpForwarding'): #disconnect idle sessions
						line = 'AllowTcpForwarding no\n'
					if MatchingLine(line,'AllowStreamLocalForwarding'): #disconnect idle sessions
						line = 'AllowStreamLocalForwarding no\n'
					if MatchingLine(line,'LoginGraceTime'): #must authenticate within grace period
						line = 'LoginGraceTime 5s\n'
					#if MatchingLine(line,'ClientAliveInterval'): #disconnect idle sessions
					#	line = 'ClientAliveInterval 600'
					#if MatchingLine(line,'ClientAliveCountMax'): #disconnect idle sessions
					#	line = 'ClientAliveCountMax 2'
					
					if MatchingLine(line,'LoginGraceTime'): #must authenticate within grace period
						line = 'LoginGraceTime 5s\n'

					#https://linux-audit.com/audit-and-harden-your-ssh-configuration/
					#By default, the SSH server can check if the client connecting maps back to the 
					#same combination of hostname and IP address. Use the option UseDNS to perform this 
					#basic check as an additional safeguard.
					#UseDNS yes

					hardened_sshd_config_lines.append(line.replace('\'','\\\''))

				return hardened_sshd_config_lines[:-1]

			def Generate_ssh_jail(new_ssh_port: int,findtime=600,bantime=6000,attempts=2,long_findtime=18000,long_bantime=6000000,long_attempts=4):
				"""Generate a fail2ban SSH jail.local text_lines.
				Args:
					new_ssh_port (int):
					findtime (int):
					bantime (int): (Seconds) that an IP would be blocked from the server if they are found to be in violation of any of the defined rules.
					attempts (int): Number of incorrect login attempts allowed for a client before they get restricted to access the server.
					long_findtime (int):
					long_bantime (int):
					long_attempts (int):
				Returns:
					list: text_lines
				Ref:
					https://www.booleanworld.com/protecting-ssh-fail2ban/
					https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-ubuntu-14-04
				"""
				ssh_jail = []
				ssh_jail.append('[sshd]')
				ssh_jail.append('')
				ssh_jail.append('enabled	= true')
				ssh_jail.append('port		= ' + str(new_ssh_port))
				ssh_jail.append('filter		= sshd')
				ssh_jail.append('logpath	= /var/log/auth.log')
				ssh_jail.append('banaction	= iptables-multiport')
				ssh_jail.append('findtime	= ' + str(findtime))
				ssh_jail.append('bantime	= ' + str(bantime))
				ssh_jail.append('maxretry	= ' + str(attempts))
				ssh_jail.append('')
				ssh_jail.append('[sshdlongterm]')
				ssh_jail.append('')
				ssh_jail.append('enabled	= true')
				ssh_jail.append('port		= ' + str(new_ssh_port))
				ssh_jail.append('filter		= sshd')
				ssh_jail.append('logpath	= /var/log/auth.log')
				ssh_jail.append('banaction	= iptables-multiport')
				ssh_jail.append('findtime	= ' + str(long_findtime))
				ssh_jail.append('bantime	= ' + str(long_bantime))
				ssh_jail.append('maxretry	= ' + str(long_attempts))
				return ssh_jail

			def BlockAllInBut(new_ssh_port: int):
				"""Block all incoming except new_ssh_port, and allow all outgoing, then enable ufw.
				Args:
					new_ssh_port (int):
				"""
				return 'ufw default deny incoming: ' +\
					'ufw default allow outgoing; ' +\
					'ufw allow ' + str(new_ssh_port) + '/tcp'

			def Harden_sysctl(sysctl_lines: list):
				"""Harden settings related to network configuration.
				Args:
					sysctl_lines (list):
				Returns:
					list: hardened_sysctl_lines
				Ref:
					https://github.com/besnik/tutorials/tree/master/linux-hardening
				"""
				def MatchingLine(line: str,pred: str):
					#pred = pred + ' = '
					if line[:len(pred)] == pred:
						return True
					if line[:len(pred)+1] == ('#' + pred):
						return True
					if pred[-1:] == '\n':
						return False
					else:
						return MatchingLine(line,pred + '\n')

				hardened_sysctl_lines = []
				for line in sysctl_lines:
					# turn on Source Address Verification in all interfaces to prevent some spoofing attacks
					if MatchingLine(line,'net.ipv4.conf.default.rp_filter'):
						line = 'net.ipv4.conf.default.rp_filter=1'
					if MatchingLine(line,'net.ipv4.conf.all.rp_filter'): #description
						line = 'net.ipv4.conf.all.rp_filter=1'

					#enable TCP/IP SYN cookies
					if MatchingLine(line,'net.ipv4.tcp_syncookies'): #description
						line = 'net.ipv4.tcp_syncookies=1'
					if MatchingLine(line,'net.ipv4.tcp_max_syn_backlog'): #description
						line = 'net.ipv4.tcp_max_syn_backlog = 2048'
					if MatchingLine(line,'net.ipv4.tcp_synack_retries'): #description
						line = 'net.ipv4.tcp_synack_retries = 2'
					if MatchingLine(line,'net.ipv4.tcp_syn_retries'): #description
						line = 'net.ipv4.tcp_syn_retries = 5'

					#do not accept ICMP redirects (prevent MITM attacks)
					if MatchingLine(line,'net.ipv4.conf.all.accept_redirects'): #description
						line = 'net.ipv4.conf.all.accept_redirects = 0'
					if MatchingLine(line,'net.ipv6.conf.all.accept_redirects'): #description
						line = 'net.ipv6.conf.all.accept_redirects = 0'
					if MatchingLine(line,'net.ipv4.conf.default.accept_redirects'): #description
						line = 'net.ipv4.conf.default.accept_redirects = 0 '
					if MatchingLine(line,'net.ipv6.conf.default.accept_redirects'): #description
						line = 'net.ipv6.conf.default.accept_redirects = 0'

					#do not send ICMP redirects (we are not a router)
					if MatchingLine(line,'net.ipv4.conf.all.send_redirects'): #description
						line = 'net.ipv4.conf.all.send_redirects = 0'
					if MatchingLine(line,'net.ipv4.conf.default.send_redirects'): #description
						line = 'net.ipv4.conf.default.send_redirects = 0'

					#do not accept IP source route packets (we are not a router)
					if MatchingLine(line,'net.ipv4.conf.all.accept_source_route'): #description
						line = 'net.ipv4.conf.all.accept_source_route = 0'
					if MatchingLine(line,'net.ipv6.conf.all.accept_source_route'): #description
						line = 'net.ipv6.conf.all.accept_source_route = 0'
					if MatchingLine(line,'net.ipv4.conf.default.accept_source_route'): #description
						line = 'net.ipv4.conf.default.accept_source_route = 0'
					if MatchingLine(line,'net.ipv6.conf.default.accept_source_route'): #description
						line = 'net.ipv6.conf.default.accept_source_route = 0'

					#log Martian Packets
					if MatchingLine(line,'net.ipv4.conf.all.log_martians'): #description
						line = 'net.ipv4.conf.all.log_martians = 1'
					if MatchingLine(line,'net.ipv4.icmp_ignore_bogus_error_responses'): #description
						line = 'net.ipv4.icmp_ignore_bogus_error_responses = 1'
					if MatchingLine(line,'net.ipv4.icmp_echo_ignore_broadcasts'): #ignore ICMP broadcast requests
						line = 'net.ipv4.icmp_echo_ignore_broadcasts = 1'
					if MatchingLine(line,'net.ipv4.icmp_echo_ignore_all'): #ignore directed pings
						line = 'net.ipv4.icmp_echo_ignore_all = 1'
					#if MatchingLine(line,'word'): #description
					#	line = 'newword'

					hardened_sysctl_lines.append(line)

				return hardened_sysctl_lines

		class Performance:
			
			def CreateSwapfile(size_gb=4):
				return 'fallocate -l ' + str(size_gb) + 'G /swapfile'
			
			def LockSwapfile():
				return 'chmod 600 /swapfile'
			
			def MarkSwapfile():
				return 'mkswap /swapfile'
			
			def EnableSwapfile():
				return 'swapon /swapfile'
			
			def PermanentizeSwapfile():
				return 'echo \'/swapfile none swap sw 0 0\' | sudo tee -a /etc/fstab'
			
			def SetSwappiness(swappiness=20):
				return 'echo \'vm.swappiness=' + str(swappiness) + '\' | sudo tee -a /etc/sysctl.conf'
			
			def SetCachePressure(pressure=50):
				return 'echo \'vm.vfs_cache_pressure=' + str(pressure) + '\' | sudo tee -a /etc/sysctl.conf'

		class Net:

			def MAC_address(interface='eth0'):
				return 'cat /sys/class/net/' + interface + '/address'

class Docker:
	"""For interacting with a running Docker instance on Windows.
	"""

	#TODO: creating dockerfiles
	#TODO: https://stackoverflow.com/questions/27757405/how-to-kill-process-inside-container-docker-top-command

	#https://docs.docker.com/config/containers/resource_constraints/
	#https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy
	#https://stackoverflow.com/questions/49377744/how-to-run-docker-image-in-ubuntu-with-vnc
	#http://blog.fx.lv/2017/08/running-gui-apps-in-docker-containers-using-vnc/
	#https://github.com/ConSol/docker-headless-vnc-container
	#https://www.howtoforge.com/tutorial/how-to-create-docker-images-with-dockerfile/
	#https://www.mirantis.com/blog/how-do-i-create-a-new-docker-image-for-my-application/
	#https://rominirani.com/docker-tutorial-series-writing-a-dockerfile-ce5746617cd

	#https://www.digitalocean.com/community/questions/why-my-docker-container-destroy-itself

	default_python = 'python3.6' #default version of python to use

	image_for_runtime = {
		#'python3.6': 'dacut/amazon-linux-python-3.6', #looks like this image no longer exists
		'python3.6': 'quiltdata/lambda',
		'ubuntu': 'ubuntu:18.04',
		}

	operation_environment = 'op_env'
	
	platform = '' #empty, but if specified, overrides the shell_executor selection

	def shell_executor():
		"""Determines the shell executor to use.
		"""
		#TODO: make this more abstract so can be used without importing Docker class
		if Docker.platform == '':
			platform = sys.platform
		else:
			platform = Docker.platform

		shells = {
			'win32': 'powershell.exe',
			'linux2': '',
			'linux': ''
			}

		return shells[platform]

	class API:
		
		def Create(container_name='default_container_name',image='',n_cpu=-1.0,mem_M=-1,swap_M=-10,additional_params={}):
			"""Command to create a container.
			Args:
				container_name (str): 'default_container_name'
				image (str): docker image to use -> see Docker.image_for_runtime.values()
				n_cpu (float): 
				mem_M (int): Mb of RAM for container
				swap_M (int): Mb of swapfile
				additional_params (dict): keys are command-line args like '--gpus', values are the values
			Returns:
				str: command string.
			Refs:
				https://docs.docker.com/engine/reference/commandline/create/
			Notes:
				If image is not set, default is Docker.image_for_runtime[Docker.default_python]
			"""

			#if no image, use default of python
			image = Docker.image_for_runtime[Docker.default_python] if image == '' else image

			base = 'docker create -it --name ' + container_name + ' '
			if n_cpu > 0:
				base = base + '--cpus="' + str(n_cpu) + '" '
			if mem_M > 0:
				base = base + '--memory=' + str(mem_M) + 'M '
			if swap_M > -1: #not allowing -1 means unlimited
				base = base + '--memory-swap=' + str(swap_M) + 'M '

			if len(list(additional_params.keys())) > 0:
				for key in list(additional_params.keys()):
					key = key + '=' if key[-1] != '=' else key
					base + key + str(additional_params[key])

			return base + image

		def Start(container_name='default_container_name'):
			"""Command to start a container.
			Args:
				container_name (str): 'default_container_name'
			Returns:
				str: command string.
			"""
			return 'docker start ' + container_name

		def Stop(container_name='default_container_name'):
			"""Command to start a container.
			Args:
				container_name (str): 'default_container_name'
			Returns:
				str: command string.
			"""
			return 'docker stop ' + container_name

		def List():
			"""Command to list containers.
			Returns:
				str: command string.
			"""
			return 'docker ps -a'

		def ArbitraryCommand(container_name='default_container_name',command='echo hello',useBash=False):
			"""Command to execute an arbitrary command.
			Args:
				container_name (str): 'default_container_name'
				command (str): 'echo hello'
				useBash (bool): Prepends command with 'bash -c'
			Returns:
				str: command string.
			"""
			if useBash:
				command = 'bash -c "' + command + '"'
			return 'docker exec ' + container_name + ' ' + command

		def PipInstall(pkg: str,environment_path:str,container_name='default_container_name'):
			"""Command to execute an arbitrary command.
			Args:
				pkg (str): Pip package to instal. 'pippkg==1.2.3'
				environment_path (str): Folder where to install.
				container_name (str): 'default_container_name'
			Returns:
				str: pip_install_command
			"""
			#TODO: pip3 is dependant on the distribution - pip3/yum stuff for AMI
			command = 'pip3 install ' + pkg + ' -t /' + environment_path
			return Docker.API.ArbitraryCommand(container_name=container_name,command=command)

		def CopyFile(container_id: str,source_filepath:str,destination_filepath: str,fromDocker=False):
			"""Copy a file into, or from, a docker container.
			Args:
				container_id (str): 'ae77tg...'
				source_filepath (str): Source filepath.
				destination_filepath (str): Destination filepath.
				fromDocker (bool): True if copying the source from docker.
			Returns:
				str: copy_command
			"""
			if fromDocker:
				return 'docker cp ' + container_id + ':' + source_filepath + ' ' + destination_filepath
			else: #copy to docker
				return 'docker cp ' + source_filepath + ' ' + container_id + ':' + destination_filepath

		def ListProcesses(container_name='default_container_name'):
			"""List running processes in a container.
			Args:
				container_name (str): Container specified by name.
			Returns:
				str: top_command
			TODO:
				ps -aux ? https://stackoverflow.com/questions/27757405/how-to-kill-process-inside-container-docker-top-command
			"""
			return 'docker top ' + container_name

		def Monitor(filepath: str):
			"""Create a monitoring log.
			Args:
				filepath (str): Filepath to write log to.
			Returns:
				str: monitor_command
			"""
			return 'docker stats --format "{{.ID}},{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}" >> ' + filepath
		
		def Id(container_name: str):
			"""Get id of a container.
			Args:
				container_name (str):
			Returns:
				str: id_command
			"""
			return 'docker ps -aqf name=' + container_name

		def Version():
			"""Get the current version of Docker.
			Returns:
				str: version_command
			"""
			return 'docker --version'

	def Create(container_name: str,runtime: str,n_cpu: float,ram_Mb: int,swap_Mb: int,additional_params={},dontExecute=False):
		"""Create a virtual compute container.
		Args:
			name (str): Name of the container.
			runtime (str): see Docker.image_for_runtime.keys(); Docker.default_python if runtime is ''
			n_cpu (float): Number of cpus to allocate for the container.
			ram_Mb (int): Mb of RAM to allocate for the container.
			swap_Mb (int): Mb of ROM to allocate for the container's use as RAM.
			additional_params (dict): see Docker.API.Create
			dontExecute (bool): Returns the API command before it can be sub process executed.
		Returns:
			str: stdout
		Ref:
			https://docs.docker.com/engine/reference/commandline/create/
		"""
		runtime = Docker.default_python if runtime == '' else runtime
		try: image = Docker.image_for_runtime[runtime]
		except: image = runtime

		create_command = Docker.API.Create(container_name=container_name,image=image,n_cpu=n_cpu,mem_M=ram_Mb,swap_M=swap_Mb,additional_params=additional_params)
		if dontExecute: return create_command
		return subprocess.check_output([Docker.shell_executor(),create_command]).decode('utf-8')

	def Start(container_name: str,dontExecute=False):
		"""Start a container.
		Args:
			container_name (str):
			dontExecute (bool): Returns the API command before it can be sub process executed.
		Returns:
			str: stdout
		"""
		start_command = Docker.API.Start(container_name)
		if dontExecute: return start_command
		return subprocess.check_output([Docker.shell_executor(),start_command]).decode('utf-8')

	def Inject(name: str,source_filepath:str,destination_filepath: str,dontExecute=False):
		"""Inject a file into a container.
		Args:
			name (str):
			source_filepath (str): Source filepath.
			destination_filepath (str): Destination filepath.
			dontExecute (bool): Returns the API command before it can be sub process executed.
		Returns:
			str: stdout
		"""
		#TODO: requires container id but argument is container name? does it matter?
		copy_command = Docker.API.CopyFile(name,source_filepath,destination_filepath)
		if dontExecute: return copy_command
		return subprocess.check_output([Docker.shell_executor(),copy_command]).decode('utf-8')

	def Command(container_name: str,command: str,useBash=False,dontExecute=False):
		"""Execute a command in a container.
		Args:
			container_name (str): Container specified by name.
			command (str): Command to execute
			useBash (bool): Use bash to execute the command in the container
			dontExecute (bool): Returns the API command before it can be sub process executed.
		Returns:
			str: stdout
		"""
		arb_command = Docker.API.ArbitraryCommand(container_name,command,useBash)
		if dontExecute: return arb_command
		return subprocess.check_output([Docker.shell_executor(),arb_command]).decode('utf-8')

	def Compile(environment_name: str,runtime: str,pip_requirements_list=None,requirements_filePath=None):
		"""Create and package a virtual python environment for a runtime using a container.
		Args:
			environment_name (str): Name for the virtual environment to create.
			runtime (str): Docker.image_for_runtime[runtime], if fails, uses the runtime as the docker image
			pip_requirements_list (list): None by default, list of pip requirements for environment -> 'mypackage==1.2.3'
			requirements_filePath (str): None by default, filePath to a requirements.txt.
		Returns:
			str: env_zip_filePath
		Notes:
			A container with the correct image should already have been created.
			Ex:
				Create a docker container with the AWS lambda image:
				docker create -it --name default_container_name lambci/lambda:python3.6'

				Interact with the container via powershell/bash
				docker exec -it container_name /bin/bash
		"""

		#check if pip dependancies required, if not, no need to package environment
		if requirements_filePath is not None:
			#read requirements txt
			with open(requirements_filePath, 'r') as infile:
				pip_package_list = infile.read()
		elif pip_requirements_list is not None:
			#use specified list
			pip_package_list = pip_requirements_list
		else:
			return None
		try:
			container_image = Docker.image_for_runtime[runtime]
		except:
			container_image = runtime
		tprint(' --Using docker image -> ' + container_image + ' to build environment -> ' + environment_name)

		#list all containers and start one with specified image
		#TODO: this starts all containers of this image, should be specified by name?
		container_list = Docker.Utils.List_Containers()
		container_name = None
		for container in container_list:

			#if container has correct image
			if container['image'] == container_image:
				container_name = container['name']
				container_id = container['id']
				
				#create base docker cmd string
				docker_cmd = 'docker exec ' + container_name + ' '

				#start the container
				start_container_output = subprocess.check_output([Docker.shell_executor(),Docker.API.Start(container_name)]).decode('utf-8')
		
		if container_name is None:
			raise ValueError('Container with image -> ' + container_image + ' doesnt exist.')
		
		#make the environment folder in the container
		try:
			mkdir_command = Docker.API.ArbitraryCommand(container_name=container_name,command='mkdir ' + environment_name)
			mkdir_output = subprocess.check_output([Docker.shell_executor(),mkdir_command]).decode('utf-8')
		except:
			#failed to make dir, already exists?
			#TODO: should delete folder incase different dependancies to install
			print('Environment folder -> ' + environment_name + ' already exists.')

		#TODO: add in installing git because some pip pkgs will be using git to pull from github
		git_install_command = Docker.API.ArbitraryCommand(command='yum install -y git',container_name=container_name)
		git_install_output = subprocess.check_output([Docker.shell_executor(),git_install_command]).decode('utf-8')

		#pip install dependancies to the environment folder
		if pip_package_list is not None: #might not need any pip installs
			print(str(datetime.now()) + ' -- Installing package requirements')
			for pkg in pip_package_list:
				if pkg != '':
					#pip_install_command = Docker.API.ArbitraryCommand(container_name=container_name,command='pip3 install ' + pkg + ' -t /' + environment_name)
					pip_install_command = Docker.API.PipInstall(pkg,environment_name,container_name=container_name)
					pip_install_output = subprocess.check_output([Docker.shell_executor(),pip_install_command]).decode('utf-8')

		#zip up the env folder
		zip_str = 'docker exec -w /' + environment_name + '/ ' +  container_name + ' zip -r ' + environment_name +'.zip ' '. -i *'
		zip_output = subprocess.check_output([Docker.shell_executor(),zip_str]).decode('utf-8')

		#move zip from the env folder to base
		move_zip_str = 'docker exec -w /' + environment_name + '/ ' + container_name + ' mv ' + environment_name +'.zip /'
		move_zip_output = subprocess.check_output([Docker.shell_executor(),move_zip_str]).decode('utf-8')

		#extract a copy of zip from docker to local
		env_zip_filePath = Docker.Utils.Extract_Environment(environment_name,container_id=container_id)

		return env_zip_filePath

	def MakeFlashLines(presigned_zip_urls: list,passphrase: str,final_commands=[],flashfile_template_filepath=None):
		"""Creates a flashfile.py that installs encrypted packages from presigned urls.
		Args:
			presigned_zip_urls (list(str)): Presigned zip urls to be downloaded and installed via the flashfile.
			passphrase (str): Passphrase to decrypt the zips
			final_commands (list(str)): Commands to be executed after the flashfile has completed installation.
		Returns:
			list(str): flash_lines
			str: flashfile_template_filepath
		"""
		
		#load the flashfile_template file into memory
		if flashfile_template_filepath == None:
			flashfile_template_filepath = os.path.dirname(os.path.abspath(__file__)) + '/flashfile_template.py'
		flash_lines = open(flashfile_template_filepath,'r').readlines()
		
		#must add escapes for single quotes
		for l in range(len(flash_lines)):
			flash_lines[l] = flash_lines[l].replace('\'','\\\'')

		#insert the passphrase
		flash_lines[flash_lines.index('#passphrase = []\n')] = 'passphrase = \\\'' + passphrase + '\\\'\n'

		#insert the presigned zip urls
		pzu_line = ''
		for pzu in presigned_zip_urls:
			pzu_line = pzu_line + '\\\'' + pzu + '\\\','
		flash_lines[flash_lines.index('#presigned_zip_urls = []\n')] = 'presigned_zip_urls = [' + pzu_line + ']\n'

		#if any final commands to be executed, insert them
		if len(final_commands) > 0:
			final_command = ''
			for fc in final_commands:
				final_command = final_command + '\\\'' + fc + '\\\','
			flash_lines[flash_lines.index('final_commands = []\n')] = 'final_commands = [' + final_command + ']\n'

		#return the text
		return flash_lines,flashfile_template_filepath

	def IsRunning():
		"""Get the Docker version.
		"""
		version_command = Docker.API.List()
		try:
			resp =  subprocess.check_output([Docker.shell_executor(),version_command]).decode('utf-8')
			return True
		except:
			return False

	class Utils:

		def List_Containers():
			"""List containers in docker.
			Returns:
				list:
			"""
			#submit api call using shell
			container_output = subprocess.check_output([Docker.shell_executor(),Docker.API.List()]).decode('utf-8')

			#split lines
			lines = container_output.split('\n')

			#get fields
			fields = [x.lower() for x in lines[0].split()]
			#len(list(filter(None,[x for x in lines[1].split('  ')])))

			#skip first line, then extract name/id/image
			container_list = []
			for l in range(1,len(lines)-1):
				#line = lines[l].split()
				line = list(filter(None,[x for x in lines[l].split('  ')]))
				container_list.append({
						'id': line[0],
						'image': line[1],
						'name': lines[l].split(' ')[-1],
						'created': line[3],
						'status': line[4],
						#ports can be empty
						})

			return container_list

		def Info(container_name: str):
			"""Get info on container by name.
			Args:
				name (str):
			Return:
				dict: container
			"""
			container_list = Docker.Utils.List_Containers()

			for container in container_list:
				if container['name'] == container_name:
					return container

			pass

		def Extract_Environment(environment_name: str, container_id: str):
			"""Copy the environment zip out of container into folder where this script is.
			Args:
				environment_name (str):
				container_id (str):
			Returns:
				str: env_zip_filepath
			"""

			curdir = (os.path.dirname(os.path.abspath(__file__)) + '\\').replace('\\', '/')
			copy_zip_str = Docker.API.CopyFile(container_id,environment_name+'.zip',curdir+environment_name+'.zip',fromDocker=True)
			copy_zip_output = subprocess.check_output([Docker.shell_executor(),copy_zip_str]).decode('utf-8')

			return curdir + environment_name + '.zip'


class Conda:
	"""
	
	"""
	#https://conda.io/docs/user-guide/configuration/use-condarc.html#specify-environment-directories-envs-dirs
	#https://github.com/conda/conda-api/blob/master/conda_api.py

	#TODO: use database and store the results from GatherRequirements -> each file can have its own environment

	conda_env_folderpath = '\\'.join(sys.prefix.split('\\')[:-1]) #set to -1 to thow error if not set

	accepted_versions = {
		'python36':'python3.6'
		}

	confusion_exceptions = {
		'Crypto': 'pycryptodome',
		'tensorflow': 'tensorflow=',
		'sklearn': ['scipy','numpy','scikit-learn'], #https://stackoverflow.com/questions/36384447/how-to-install-sklearn
		'pygments': 'Pygments',
		'kivy': 'Kivy',
		'security': 'Security',
		'secretsharing': 'secret-sharing',
		}

	github_packages = {
		'secretsharing': 'git+https://github.com/blockstack/secret-sharing',
		'security': 'git+https://github.com/pmp47/Security',
		#https://stackoverflow.com/questions/4830856/is-it-possible-to-use-pip-to-install-a-package-from-a-private-github-repository

		}

	github_access_token = ''

	class API:
		def Info(as_json=True):
			additional = ' --json' if as_json else ''
			return 'info' + additional

		def ListInstalls(env_name: str,as_json=True):
			#https://docs.conda.io/projects/conda/en/latest/commands/list.html
			additional = ' --json' if as_json else ''
			return 'list -n ' + env_name + additional

	def List_Installs(env_name: str):
		"""List all installed packages by Conda Environment name. Be sure to specify Conda.conda_env_folderpath.
		Args:
			env_name (str): Conda environment name.
		Returns:
			list: pip_installs,
			str: python_version
		"""

		#TODO: use this instead
		#return subprocess.check_output(Conda.API.ListInstalls(env_name),shell=True)
		#pkgs = json.loads(Conda.Utils.call_conda(Conda.API.ListInstalls(env_name)))

		#get items in site-packages
		items = os.listdir(Conda.conda_env_folderpath + '\\' + env_name + '\\Lib\\site-packages')
		site_packages = np.array(items)[npe.find_contains('-info',items)].tolist()

		pip_installs = []
		for pkg in site_packages:
			splits = pkg.split('-')
			
			requirement = splits[0] + '==' + splits[1].split('.dist')[0]
			requirement = requirement.replace('_','-')
			#not changing to git here, thats in formatting
			#try: #TODO: see if in github collections
			#	requirement = Conda.github_packages[splits[0]]
			#	a = 5
			#except:
			#	a = 5
			pip_installs.append(requirement)

		base_items = os.listdir(Conda.conda_env_folderpath + '\\' + env_name)
		dlls = np.array(base_items)[npe.find_contains('.dll',base_items)].tolist()
		debuggers = np.array(base_items)[npe.find_contains('.pdb',base_items)].tolist()

		python_versions = []
		for pdb in debuggers:
			name = pdb.split('.')[0]
			same_in_dlls = np.array(dlls)[npe.find_contains(name,dlls)].tolist()
			if len(same_in_dlls):
				for version_found in same_in_dlls:
					try:
						python_versions.append(Conda.accepted_versions[version_found.split('.')[0]])
					except:
						#not an accepted version
						None

		python_versions = list(set(python_versions))
		if len(python_versions) > 1:
			raise ValueError('No python version found?')

		return list(set(pip_installs)),python_versions[0]

	def List_Requirements(seed_filePath: str):
		"""List the requirements for a filepath *.py
		Args:
			seed_filePath (str): Filepath of a python script with proper requirements tags.
		Returns:
			list: pip_installs_required
			list: customs_required
		"""

		pip_installs_required = []
		customs_required = []
		builtins = []

		#read the file
		with open(seed_filePath, 'r') as infile:
			text = infile.read()

			try:
				requirements_text = text.split('--start requirements--')[1].split('--end requirements--')[0]
				text.split('--end requirements--')[1]
			except:
				raise ValueError('File does not contain proper requirements tags')

			#extract all the pip imports and froms
			pip_install_lines = requirements_text.split('#customs')[0].split('\n')[1:]
			for pline in pip_install_lines:
				if len(pline) > 0:
					if '#' not in pline[0]:
						pip_installs_required.append(pline.split(' ')[1].split('.')[0])

			#extract all the customs imports and froms
			customs_lines = requirements_text.split('#customs')[1].split('builtins')[0].split('\n')
			for cline in customs_lines:
				if len(cline) > 0:
					if '#' not in cline[0]:
						cpkg = cline.split(' ')[1].split('.')[0] + '.py'
						customs_required.append(cpkg)

		#should be unique
		pip_installs_required = list(set(pip_installs_required))
		customs_required = list(set(customs_required))

		return pip_installs_required,customs_required

	def Gather_Requirements(func_filepath: str,env_name: str):
		"""Gather list of pip requirements for a function file.
		Args:
			func_filepath (str): Filepath of specified function *.py
			env_name (str): Conda environment name.
		Returns:
			list: pip_requirements
			list: sup_filepaths
			str: runtime
		"""

		#get all pips available in environment
		pip_installs,run_time = Conda.List_Installs(env_name)

		#list pips required for func file
		pip_installs_required,custom_scripts = Conda.List_Requirements(func_filepath)
		sup_Filepaths_list = []
		for custom_script in custom_scripts:
			#assume customs are located in same folder as func target file

			#TODO: use coidefactory?

			splits = func_filepath.replace('/','\\').split('\\')[0:-1]
			splits[0] = splits[0] + '\\'
			custom_filePath = os.path.join(*splits) + '\\' + custom_script# + '.py'
			sup_Filepaths_list.append(custom_filePath)

		#remove installs not required
		pip_requirements_list = Conda.Utils.FormatRequirements(pip_installs,pip_installs_required)

		#if there are supplimentary files
		if len(sup_Filepaths_list) > 0:
			for sup_Filepath in sup_Filepaths_list:

				new_pip_requirements_list, new_sup_Filepaths_list,_ = Conda.Gather_Requirements(sup_Filepath,env_name)
				pip_requirements_list = pip_requirements_list + new_pip_requirements_list
				sup_Filepaths_list = sup_Filepaths_list + new_sup_Filepaths_list

		#make lists unique
		pip_requirements_list = list(set(pip_requirements_list))
		sup_Filepaths_list = list(set(sup_Filepaths_list))

		#if pip_requirements_list has 'tensorflow'
		#add https://storage.googleapis.com/tensorflow/linux/cpu/tensorflow-1.12.0-cp36-cp36m-linux_x86_64.whl

		return pip_requirements_list, sup_Filepaths_list,run_time

	class Utils:

		def FormatRequirements(pip_installs: list,pip_installs_required: list):
			"""Format requirements by verifying package was found in the installs.
			Args:
				pip_installs (list): List of pip packages installed in the Conda environment.
				pip_installs_required (list): List of pip packages required for a specified function.
			Returns:
				list: pip_requirements_list
			"""

			pip_requirements_list = []
			for pkg in pip_installs_required:

				#see if package is in pip installs
				pkg_requirements = np.array(pip_installs)[npe.find_contains(pkg,pip_installs)].tolist()


				if len(pkg_requirements) != 1: #either too many or none

					#check if has a different name or is actually multiple packages

					pkg_aliai = Conda.confusion_exceptions[pkg]
					if isinstance(pkg_aliai,list):
						for alias in pkg_aliai:
							pkg_req = np.array(pip_installs)[npe.find_contains(alias,pip_installs)].tolist()
							if len(pkg_req) == 1:
								pkg_requirements.append(pkg_req[0])
							else:
								raise ValueError('How was more than 1 package found? potentially installed multiple version of same package?')
					else:
						pkg_requirements = np.array(pip_installs)[npe.find_contains(pkg_aliai,pip_installs)].tolist()

					a = 5
				else: #had a single result

					#is this result actually a git package?
					try:
						#get the repo link
						repo_link = Conda.github_packages[pkg]

						#get the version
						version = '==' + pkg_requirements[0].split('==')[-1]

						#add the specific version (DEFAULT MASTER BRANCH)
						git_link = repo_link + '.git@master#egg=' + Conda.confusion_exceptions[pkg] + version #reponame differ from package

						pkg_requirements = [git_link]
					except Exception as ex:
						#was not a git link

						#ook so assume its a pipy and correct name

						a = 5

					a = 5


				for req in pkg_requirements:
					pip_requirements_list.append(req)

			return pip_requirements_list

		def call_conda(arg_list: list, abspath=True):
			"""Call conda using a subprocess.
			References:
				https://github.com/conda/conda-api/blob/master/conda_api.py
			"""
			# call conda with the list of extra arguments, and return the tuple
			# stdout, stderr
			if abspath:
				#TODO: this may not always be?
				ROOT_PREFIX = [x for x in os.environ['PATH'].split(';') if 'conda' in x][1]
				if sys.platform == 'win32':
					python = os.path.join(ROOT_PREFIX, 'python.exe')
					conda  = os.path.join(ROOT_PREFIX, 'Scripts', 'conda-script.py')
				else:
					python = os.path.join(ROOT_PREFIX, 'bin/python')
					conda  = os.path.join(ROOT_PREFIX, 'bin/conda')
				cmd_list = [python, conda]
			else: # just use whatever conda is on the path
				cmd_list = ['conda']

			cmd_list.extend(arg_list)

			pipe = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			
			return pipe.communicate()[0].decode()


class Container:
	"""Virtual container.
	Args:
		runtime (str):
		mem_M 
		swap_M
		n_cpu
		network
		environment_name (str):
	TODO:
		need a container object so can stored all these commands and stuff and pull/execute/update them very easily
	"""
	
	services = {
		'docker': Docker,
		}
	def __init__(self,kwargs):

		self.runtime = kwargs['runtime']
		self.mem_M = kwargs['mem_M']
		self.swap_M = kwargs['swap_M']
		self.n_cpu = kwargs['n_cpu']
		self.network = kwargs['network']
		self.environment_name = kwargs['environment_name']
		
		self.bashfile_filepath = None
		return super().__init__()

	def IsServiceRunning(service: str):
		"""Determine if the service is running.
		Args:
			service (str): 'docker' |
		Returns:
			bool:
		"""
		return Container.services[service].IsRunning()

	def List(service='docker'):
		"""Determine if the service is running.
		Returns:
			bool:
		"""
		return Container.services[service].Utils.List_Containers()

	def Run(self,name: str,service='docker',dontExecute=False):
		"""Run this container using an installed container service.
		Args:
			name (str): Unique name for this container.
			service (str): Container service. 'docker' |
		Returns:
			list(str): commands or responses depending on if executed
		"""
		if self.bashfile_filepath == None:
			raise ValueError('bashfile_filepath not set yet.')

		#record responses (or commands)
		commands = []

		tprint(' -- Creating container ' + name + ' -- ')
		commands.append(Container.services[service].Create(name=name,runtime=self.runtime,n_cpu=self.n_cpu,ram_Mb=self.mem_M,swap_Mb=self.swap_M,network=self.network,dontExecute=dontExecute))

		tprint(' -- Starting container ' + name + ' -- ')
		commands.append(Container.services[service].Start(name=name,dontExecute=dontExecute))

		tprint(' -- Injecting bashfile -- ')
		commands.append(Container.services[service].Inject(name,self.bashfile_filepath,'/bashfile.sh',dontExecute=dontExecute))

		tprint(' -- Executing bashfile -- ')
		commands.append(Container.services[service].Command(name,'/bashfile.sh',useBash=True,dontExecute=dontExecute)) #use bash?

		return commands

class Tests:
	def main():

		pass
