#--start requirements--
#pip installs
from digitalocean import SSHKey, Droplet, Manager, Firewall, InboundRule, OutboundRule, Destinations, Sources
from paramiko import SSHClient, RSAKey, AutoAddPolicy

#customs
from dictableobj import UniqueStatusObject, SecurableObject, DictableObj

#builtins
import socket

#--end requirements--

class DigitalOcean:
	"""DigitalOcean cloud computing service wrapper.
	Args:
		access_token (str): 
		region (str):
	TODO:
		#return digo.manager.get_all_domains()
		#get_all_floating_ips
		#get_all_load_balancers
		#get_all_certificates
		#get_all_volumes
		#get_all_tags
		#get_all_snapshots
		#get_droplet_snapshots
		#get_volume_snapshots
		#get_all_firewalls
	"""

	#https://news.ycombinator.com/item?id=7498861

	def __init__(self,kwargs):
		#configure the resource via credentials
		self.access_token = kwargs['access_token']
		self.manager = Manager(token=self.access_token)
		self.region = kwargs['region']
		return super().__init__()

	def AccountInfo(digo):
		"""Account Info specified by provided credentials.
		Args:
			digo (DigitalOcean): Instantiated DigitalOcean credential object.
		Returns:
			Account: obj with various account info.
		"""
		return digo.manager.get_account()

	def ListRegions(digo):
		"""Regions available for this account.
		Args:
			digo (DigitalOcean): Instantiated DigitalOcean credential object.
		Returns:
			list: List of Region objs.
		"""
		return digo.manager.get_all_regions()
	
	class Domain:
		"""Sub-class for using DigitalOcean to manage a domain.
		Ref:
			https://www.digitalocean.com/community/tutorials/how-to-point-to-digitalocean-nameservers-from-common-domain-registrars
		"""
		

		def abc():
			#
			#domain = digitalocean.Domain(name='example.com', token=self.token)
			#domain.load()
			#destroy
			#domain.create_new_domain_record(type="CNAME", name="www", data="@")
			#get_records
			pass

	class Security:
		"""Sub class for services strictly for security.
		"""

		class FirewallRule:
			"""A Firewall rule.
			Attributes:
				protocol (str): 'tcp' | 'udp' | 'icmp'
				ports (str): '8000-9000'
				target_droplet_ids (list): []
				target_tags (list): ['from_droplets_tag'],
				target_ip_addresses (list): ['18.0.0.0/8'],
				load_balancer_uids (list): ['4de7ac8b-495b-4884-9a69-1050c6793cd6']
			"""

			def __init__(self,kwargs):
				#configure the resource via credentials
				self.protocol = kwargs['protocol']
				self.ports = kwargs['ports']
				self.target_droplet_ids = kwargs['target_droplet_ids']
				self.target_tags = kwargs['target_tags']
				self.target_ip_addresses = kwargs['target_ip_addresses']
				self.load_balancer_uids = kwargs['load_balancer_uids']
				return super().__init__()

			def monitoringmetrics_outbound_rule():
				"""Firewall outbound rule for sending monitoring agent metrics.
				Returns:
					FirewallRule: firewall_rule
				Ref:
					https://www.digitalocean.com/community/questions/firewall-prevents-do-agent-from-pushing-monitoring-data
				"""
				return DigitalOcean.Security.FirewallRule({
					'protocol': 'tcp',
					'ports': '443',
					'target_droplet_ids': [],
					'target_tags': [],
					'target_ip_addresses': [socket.gethostbyname('sonar.digitalocean.com'),\
						socket.gethostbyname('repos.sonar.digitalocean.com')],
					'load_balancer_uids': []
					})
			
			def monitoringauth_outbound_rule():
				"""Firewall outbound rule for monitoring agent authorization.
				Returns:
					FirewallRule: firewall_rule
				Ref:
					https://www.digitalocean.com/community/questions/firewall-prevents-do-agent-from-pushing-monitoring-data
				"""
				return DigitalOcean.Security.FirewallRule({
					'protocol': 'tcp',
					'ports': '80',
					'target_droplet_ids': [],
					'target_tags': [],
					'target_ip_addresses': ['169.254.169.254'],
					'load_balancer_uids': []
					})
			
			def ssh_inbound_rule():
				"""Firewall inbound rule for SSH communication.
				Returns
					FirewallRule: firewall_rule
				"""
				return DigitalOcean.Security.FirewallRule({
					'protocol': 'tcp',
					'ports': '22',
					'target_droplet_ids': [],
					'target_tags': [],
					'target_ip_addresses': ['0.0.0.0/0'],
					'load_balancer_uids': []
					})
			
			def docker_outbound_rule():
				"""Firewall inbound rule for SSH communication.
				Returns
					FirewallRule: firewall_rule
				Ref:
					#https://stackoverflow.com/questions/43537237/unable-to-pull-docker-image-repository-not-found
				"""
				return DigitalOcean.Security.FirewallRule({
					'protocol': 'tcp',
					'ports': '53',
					'target_droplet_ids': [],
					'target_tags': [],
					'target_ip_addresses': [socket.gethostbyname('dseasb33srnrn.cloudfront.net'), #https://github.com/docker/for-mac/issues/357
						socket.gethostbyname('auth.docker.io'),#https://forums.docker.com/t/auth-docker-io-on-192-168-65-1-53-no-such-host/16801/4
						socket.gethostbyname('elb-registry.us-east-1.aws.dckr.io'), #https://forums.docker.com/t/auth-docker-io-on-192-168-65-1-53-no-such-host/16801/4
						socket.gethostbyname('us-east-1-elbregis-10fucsvj1tcgy-133821800.us-east-1.elb.amazonaws.com'), #https://forums.docker.com/t/auth-docker-io-on-192-168-65-1-53-no-such-host/16801/4
						socket.gethostbyname('registry-1.docker.io'),\
						socket.gethostbyname('registry-origin.docker.io'),\
						socket.gethostbyname('index.docker.io'), #https://success.docker.com/article/i-cant-reach-docker-hub-from-my-home-network
						socket.gethostbyname('elb-io.us-east-1.aws.dckr.io'), #https://success.docker.com/article/i-cant-reach-docker-hub-from-my-home-network
						socket.gethostbyname('us-east-1-elbio-rm5bon1qaeo4-623296237.us-east-1.elb.amazonaws.com')], #https://success.docker.com/article/i-cant-reach-docker-hub-from-my-home-network
					'load_balancer_uids': []
					})
			
			def all_tcp_outbound_rule():
				"""Firewall outbound rule for monitoring agent authorization.
				Returns
					FirewallRule: firewall_rule
				Ref:
					https://www.digitalocean.com/community/questions/firewall-prevents-do-agent-from-pushing-monitoring-data
				"""
				return DigitalOcean.Security.FirewallRule({
					'protocol': 'tcp',
					'ports': 'all',
					'target_droplet_ids': [],
					'target_tags': [],
					'target_ip_addresses': ['0.0.0.0/0','::/0'],
					'load_balancer_uids': []
					})
			
			def all_udp_outbound_rule():
				"""Firewall outbound rule for monitoring agent authorization.
				Returns:
					FirewallRule: firewall_rule
				Ref:
					https://www.digitalocean.com/community/questions/firewall-prevents-do-agent-from-pushing-monitoring-data
				"""
				return DigitalOcean.Security.FirewallRule({
					'protocol': 'udp',
					'ports': 'all',
					'target_droplet_ids': [],
					'target_tags': [],
					'target_ip_addresses': ['0.0.0.0/0','::/0'],
					'load_balancer_uids': []
					})

		def ListSSHKeys(digo):
			"""List all SSH keys available.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
			Returns:
				list: all_ssh_keys
			"""
			return digo.manager.get_all_sshkeys()

		def Add_SSHKey(digo,tag: str,open_ssh_key: str):
			"""Add a new OpenSSH key.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				tag (str):
				open_ssh_key (str): asymKeys['public']?
			Returns
				SSHKey: DigitalOcean SSHKey.
			"""
			key = SSHKey(token=digo.access_token,name=tag,public_key=open_ssh_key)
			resp = key.create()
			return key

		def Create_Firewall(digo,name: str,droplet_ids: list,tag: str,inbound_rules: list, outbound_rules: list):
			"""Create a Firewall.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				name (str): Name of firewall.
				droplet_ids (list): List of int droplets specified by id.
				tag (str): Tags to assign.
				inbound_rules = [FirewallRule({
					'protocol': 'tcp' | 'udp' | 'icmp',
					'ports': '8000-9000',
					'target_droplet_ids': [],
					'target_tags': ['from_droplets_tag'],
					'target_ip_addresses': ['18.0.0.0/8'],
					'load_balancer_uids': ['4de7ac8b-495b-4884-9a69-1050c6793cd6']
					})]
				outbound_rules = [FirewallRule({
					'protocol': 'tcp' | 'udp' | 'icmp',
					'ports': '8000-9000',
					'target_droplet_ids': [],
					'target_tags': ['to_droplets_tag'],
					'target_ip_addresses': ['0.0.0.0/0','::/0'],
					'load_balancer_uids': ['4de7ac8b-495b-4884-9a69-1050c6793cd6']
					})]
			Returns:
				Firewall: firewall object.
			Ref:
				https://www.digitalocean.com/docs/networking/firewalls/overview/
			"""
			
			#add inbound rules
			ibrs = []
			for ibr in inbound_rules:
				ibrs.append(InboundRule(
					protocol=ibr.protocol,
					ports=ibr.ports,
					sources=Sources(
						load_balancer_uids=ibr.load_balancer_uids,
						addresses=ibr.target_ip_addresses,
						tags=ibr.target_tags,
						droplet_ids=ibr.target_droplet_ids
						)
					)
				)

			#add outbound rules
			obrs = []
			for obr in outbound_rules:
				obrs.append(OutboundRule(
					protocol=obr.protocol,
					ports=obr.ports,
					destinations=Destinations(
						load_balancer_uids=obr.load_balancer_uids,
						addresses=obr.target_ip_addresses,
						tags=obr.target_tags,
						droplet_ids=obr.target_droplet_ids
						)
					)
				)
			
			#configure and create
			firewall = Firewall(
				token=digo.access_token,
				name=name,
				tags=[tag],
				inbound_rules=ibrs,
				outbound_rules=obrs,
				droplet_ids=droplet_ids)
			firewall.create()

			return firewall

		def AddDropletToFireWall(digo,droplet_ids: list):
			"""Add specified list of droplets to a firewall configuration.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				droplet_ids (list): List of droplet ids.

			"""
			firewall = Firewall(
				token=digo.access_token,
				name=name,
				tags=[tag]).load()
			
			firewall.add_droplets(droplet_ids)

	class Droplet:
		"""Sub class for managing droplets.

		TODO:
			Automate sizes_by_price collection -> https://www.digitalocean.com/pricing/

		"""
		#TODO: droplet. -> 
		#power_on
		#reboot
		#power_cycle
		#reset_root_password
		#take_snapshot
		#resize
		#restore
		#rebuild
		#enable_backups
		#disable_backups
		#rename
		#enable_private_networking
		#enable_ipv6
		#change_kernel
		#get_action
		#get_kernel_available

		
		sizes_by_price = {
			5: 's-1vcpu-1gb',
			10: 's-1vcpu-2gb',
			15: lambda s: {
				13: 's-1vcpu-3gb',
				22: 's-2vcpu-2gb',
				31: 's-3vcpu-1gb'
				},
			20: 's-2vcpu-4gb',
			40: 's-4vcpu-8gb',
			80: 's-6vcpu-16gb',
			}

		def ListSizes(digo):
			"""List all droplet sizes available.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
			Returns:
				list: List of Size objs.
			"""
			return digo.manager.get_all_sizes()

		def ListAll(digo):
			"""List all droplets available.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
			Returns:
				list: List of Droplet objs.
			"""
			return digo.manager.get_all_droplets()

		def ListImages(digo):
			"""List all global images available.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
			Returns:
				list: List of Image objs.
			"""
			#return digo.manager.get_all_images()
			#return digo.manager.get_my_images()
			#get_distro_images
			#get_app_images
			return digo.manager.get_global_images()

		def Exists(digo,names: list):
			"""Checks if Droplets already exists specified by name.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				names (list): Droplets specified by name to check if exists.
			Returns:
				dict: contains keys of names of droplets that exist
			"""
			droplets = digo.manager.get_all_droplets()
			exists = {}
			for droplet in droplets:
				for name in names:
					if droplet.name == name:
						exists[name] = True
			return exists

		def Create(digo,name: str,tag: str,open_ssh_key: str,image='docker-18-04',price=0,user_data='echo hello world',autoBackups=False,useMonitoring=False,ipv6=False):
			"""Creates a Droplet.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				name (str): DNS valid name.
				tag (str): Project tag?
				open_ssh_key (str): 'ssh-rsa AAGSDG...'
				image (str): OS image.
				price (int): Machine hardware designated by price.
				autoBackups (bool): True to use auto backup feature.
				useMonitoring (bool): True to use DO Agent to send out monitoring data.
				ipv6 (bool): True to assign ipv6 address.
			Returns:
				SSHKey:
				Droplet:
			"""

			if not DigitalOcean.Droplet.Utils.isValidNameorTag(name): raise ValueError('invalid host name')
			if not DigitalOcean.Droplet.Utils.isValidNameorTag(tag): raise ValueError('invalid tag')

			#add the ssh key
			try:
				key = DigitalOcean.Security.Add_SSHKey(digo,tag,open_ssh_key)
			except Exception as ex:
				#already exists
				keys = DigitalOcean.Security.ListSSHKeys(digo)
				for key in keys:
					if key.public_key == open_ssh_key:
						break

			droplet = Droplet(
				token=digo.access_token,
				name=name,
				region=digo.region,
				image=image,
				size_slug=DigitalOcean.Droplet.sizes_by_price[price],
				tags=[tag],
				ssh_keys=[key],
				backups=autoBackups, #???
				user_data=user_data, #command to run?
				monitoring=useMonitoring, #https://www.digitalocean.com/docs/monitoring/overview/
				ipv6=ipv6)
			droplet.create()

			return key, droplet

		def CreateMultiple(digo,names: list,tag: str,open_ssh_key: str,image='docker-18-04',price=0,user_data='echo hello world',autoBackups=False,useMonitoring=False,ipv6=False):
			"""Creates multiple Droplets.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				names (list): DNS valid names.
				tag (str): Project tag?
				open_ssh_key (str): 'ssh-rsa AAGSDG...'
				image (str): OS image.
				price (int): Machine hardware designated by price.
				autoBackups (bool): True to use auto backup feature.
				useMonitoring (bool): True to use DO Agent to send out monitoring data.
				ipv6 (bool): True to assign ipv6 address.
			Returns:
				SSHKey:
				list(Droplet):
			"""

			for name in names: 
				if not DigitalOcean.Droplet.Utils.isValidNameorTag(name): raise ValueError('invalid host name')
			if not DigitalOcean.Droplet.Utils.isValidNameorTag(tag): raise ValueError('invalid tag')
			#add the ssh key
			try:
				key = DigitalOcean.Security.Add_SSHKey(digo,tag,open_ssh_key)
			except Exception as ex:
				#already exists
				keys = DigitalOcean.Security.ListSSHKeys(digo)
				for key in keys:
					if key.public_key == open_ssh_key:
						break

			droplets = Droplet.create_multiple(
				token=digo.access_token,
				names=names,
				region=digo.region,
				image=image,
				size_slug=DigitalOcean.Droplet.sizes_by_price[price],
				tags=[tag],
				ssh_keys=[key],
				backups=autoBackups, #???
				user_data=user_data, #command to run?
				monitoring=useMonitoring, #https://www.digitalocean.com/docs/monitoring/overview/
				ipv6=ipv6)

			return key, droplets

		def Destroy(digo,tag: str):
			"""Destroys all droplets with a specified tag.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				tag (str): Tag specifying droplets to delete.
			"""
			droplets = digo.manager.get_all_droplets(tag_name=tag)
			for droplet in droplets:
				droplet.destroy()
			return None

		def Shutdown(digo,tag: str):
			"""Shutdowns droplets with a specified tag.
			Args:
				digo (DigitalOcean): Instantiated DigitalOcean credential object.
				tag (str): Tag specifying droplets to delete.
			"""
			droplets = digo.manager.get_all_droplets(tag_name=tag)
			for droplet in droplets:
				droplet.shutdown()
			return None

		class Utils:

			def isValidNameorTag(name_or_tag: str):
				"""Test if a name or tag for a droplet is valid
				Args:
					name_or_tag (str):
				Returns:
					bool:
				"""
				if '_' in name_or_tag: return False
				if ' ' in name_or_tag: return False
				return True

		class Monitor:

			def GetDOAgentData(digo,username,password,mfa_key):

				#stripped from the browser console app for digitalocean
				#login
				#go to droplet, refresh the graph
				#these api calls are made
				#session login is handled by user, non API access

				#TODO: use a browser automation tool like selenium, and log in
				#then only need to GET the url, provide session cookies from the login session
				#https://stackoverflow.com/questions/7164679/how-to-send-cookies-in-a-post-request-with-the-python-requests-library

				#this uses the brower's api so a raw login is required
				#url1 = 'https://cloud.digitalocean.com/sessions'

				#https://cloud.digitalocean.com/login/tfa


				#url = 'https://cloud.digitalocean.com/api/v1/monitors/metrics/aggregate?
				#dropletID[]=123456768&
				#start=1546049274&end=1546135674&
				#queries[]=sonar_memory_memtotal&queries[]=sonar_disk_space&queries[]=sonar_network_receive_bits&queries[]=sonar_network_transmit_bits&queries[]=sonar_cpu&queries[]=sonar_disk_bytes_written&queries[]=sonar_disk_bytes_read'

				pass

class Tests:

	def main():

		pass

	def keys(digo):

		res = DigitalOcean.Security.Add_SSHKey(digo,'test api key',2)
		keys = DigitalOcean.Security.ListSSHKeys(digo)

		pass

	def fw(digo):
		outbound_rules = []
		outbound_rules.append(DigitalOcean.Security.FirewallRule.monitoringauth_outbound_rule())
		outbound_rules.append(DigitalOcean.Security.FirewallRule.monitoringmetrics_outbound_rule())
		ssh_inbound_rule = DigitalOcean.Security.FirewallRule.ssh_inbound_rule()
		firewall = DigitalOcean.Security.Create_Firewall(digo,'test-fw',[120],'test-tag',[ssh_inbound_rule],outbound_rules)
		pass

	def create_list_shutdown_destroy(digo):

		raise ValueError('assert?')
		resp = DigitalOcean.Droplet.Create(digo,'testdroplet','test_tag',price=5)
		droplets = DigitalOcean.Droplet.ListAll(digo)
		resp = DigitalOcean.Droplet.Shutdown(digo,'test_tag')
		res = droplets[0].destroy()
		#accnt_info = DigitalOcean.AccountInfo(digo)
		#regions = DigitalOcean.ListRegions(digo)
		sizes = DigitalOcean.Droplet.ListSizes(digo)
		images = DigitalOcean.Droplet.ListImages(digo)
		droplets = DigitalOcean.Droplet.ListAll(digo)
		key, droplets = DigitalOcean.Droplet.CreateMultiple(digo,\
			['node-1'],'test-tag',droplet_ssh_key['public'],\
			price=5)
		node1_exists = DigitalOcean.Droplet.Exists(digo,'node-1')

		pass