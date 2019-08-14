#--start requirements--
#pip installs

#customs
#import flashfile_template

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


	image_for_runtime = {
		'python3.6': 'dacut/amazon-linux-python-3.6', #TODO: this image should determine useYum for Linux.API....
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
			'linux2': '',
			'linux': ''
			}

		return shells[platform]

	class API:
		
		#TODO: build using dockerfile_lines or specify filepath

		def Create(container_name='default_container_name',image='dacut/amazon-linux-python-3.6',\
			n_cpu=-1.0,mem_M=-1,swap_M=-10,network=''):
			"""Command to create a container.
			Args:
				container_name (str): 'default_container_name'
				image (str): 'dacut/amazon-linux-python-3.6'
				n_cpu (float): 
				mem_M (int): Mb of RAM for container
				swap_M (int): Mb of swapfile
				network (str): join a network like 'host'
			Returns:
				str: command string.
			"""
			#return 'docker create -it --network host --name ' + container_name + ' ' + image
			base = 'docker create -it --name ' + container_name + ' '
			if n_cpu > 0:
				base = base + '--cpus="' + str(n_cpu) + '" '
			if mem_M > 0:
				base = base + '--memory=' + str(mem_M) + 'M '
			if swap_M > -1: #-1 means unlimited
				base = base + '--memory-swap=' + str(mem_M) + 'M '
			if len(network) > 0:
				base = base + '--network=' + network + ' '
			return base + image

		def Start(container_name='default_container_name'):
			"""Command to start a container.
			Args:
				container_name (str): 'default_container_name'
			Returns:
				str: command string."""
			return 'docker start ' + container_name

		def Stop(container_name='default_container_name'):
			"""Command to start a container.
			Args:
				container_name (str): 'default_container_name'
			Returns:
				str: command string."""
			return 'docker stop ' + container_name

		def List():
			"""Command to list containers.
			Returns:
				str: command string."""
			return 'docker ps -a'

		def ArbitraryCommand(container_name='default_container_name',command='echo hello',useBash=False):
			"""Command to execute an arbitrary command.
			Args:
				container_name (str): 'default_container_name'
				command (str): 'echo hello'
			Returns:
				str: command string."""
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
				str: command string."""
			#TODO: pip3 is dependant on the distribution - pip3/yum stuff for AMI
			command = 'pip3 install ' + pkg + ' -t /' + environment_path
			return Docker.API.ArbitraryCommand(container_name=container_name,command=command)

		def CopyFile(container_id: str,source_filepath:str,destination_filepath: str,fromDocker=False):
			"""Copy a file into, or from, a docker container.
			Args:
				container_id (str): 'ae77tg...'
				source_filepath (str): Source filepath.
				destination_filepath (str): Destination filepath.
				fromDocker (bool): True if copying the source from docker."""
			if fromDocker:
				return 'docker cp ' + container_id + ':' + source_filepath + ' ' + destination_filepath
			else: #copy to docker
				return 'docker cp ' + source_filepath + ' ' + container_id + ':' + destination_filepath

		def ListProcesses(container_name='default_container_name'):
			#TODO: ps -aux ? https://stackoverflow.com/questions/27757405/how-to-kill-process-inside-container-docker-top-command
			return 'docker top ' + container_name

		def Monitor(filepath: str):
			"""Create a monitoring log."""
			return 'docker stats --format "{{.ID}},{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}" >> ' + filepath
		
		def Id(name: str):
			"""Get id of a container specified by name."""
			return 'docker ps -aqf name=' + name

		def Version():
			"""Get the current version of Docker."""
			return 'docker --version'

	def Create(name: str,runtime: str,n_cpu: float,ram_Mb: int,swap_Mb: int,network='',dontExecute=False):
		"""Create a virtual compute container.
		Args:
			name (str):
			runtime (str):
			n_cpu (float):
			ram_Mb (int):
			swap_Mb (int):
			network (str):
		Returns:
			str: stdout
		"""
		try: image = Docker.image_for_runtime[runtime]
		except: image = runtime

		create_command = Docker.API.Create(container_name=name,image=image,n_cpu=n_cpu,mem_M=ram_Mb,swap_M=swap_Mb,network=network)
		if dontExecute: return create_command
		return subprocess.check_output([Docker.shell_executor(),create_command]).decode('utf-8')

	def Start(name: str,dontExecute=False):
		"""Start a container.
		Args:
			name (str):
			dontExecute (bool): Whether to execute the start command using a subprocess.
		Returns:
			str: stdout
		Notes:
			If dontExecute, then the start_command api command is returned.
		"""
		start_command = Docker.API.Start(name)
		if dontExecute: return start_command
		return subprocess.check_output([Docker.shell_executor(),start_command]).decode('utf-8')

	def Inject(name: str,source_filepath:str,destination_filepath: str,dontExecute=False):
		"""Inject a file into a container.
		Args:
			name (str):
			source_filepath (str): Source filepath.
			destination_filepath (str): Destination filepath.
		Returns:
			str: stdout
		"""
		#TODO: cant do dontExecute becauserequires container id ??????
		copy_command = Docker.API.CopyFile(name,source_filepath,destination_filepath)
		if dontExecute: return copy_command
		return subprocess.check_output([Docker.shell_executor(),copy_command]).decode('utf-8')

	def Command(name: str,command: str,useBash=False,dontExecute=False):
		"""Execute a command in a container.
		Args:
			name (str):
			command (str):
			useBash (bool):
		Returns:
			str: stdout
		"""
		arb_command = Docker.API.ArbitraryCommand(name,command,useBash)
		return subprocess.check_output([Docker.shell_executor(),arb_command]).decode('utf-8')

	def Compile(environment_name: str,runtime: str,pip_requirements_list=None,requirements_filePath=None):
		"""Create and package a virtual python environment for a runtime using a container.
		Args:
			environment_name (str): String name for the virtual environment to create.
			runtime (str): Docker.image_for_runtime[runtime], if fails, uses the runtime as the docker image
			pip_requirements_list (list): None by default, list of pip requirements for environment -> 'mypackage==1.2.3'
			requirements_filePath (str): None by default, filePath to a requirements.txt.
		Returns:
			str: env_zip_filePath
		
		Notes:
			A container with the correct image should already have been created.
			Ex:
				Create a docker container with the AWS lambda image:
				docker create -it --name default_container_name dacut/amazon-linux-python-3.6

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
		print(str(datetime.now()) + ' --Using docker image -> ' + container_image + ' to build environment -> ' + environment_name)

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

		#inser the presigned zip urls
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
