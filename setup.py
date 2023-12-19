from setuptools import setup
setup(name='Cloud',
	version='1.3.2',
	description='A wrapping library focused on automating conventional cloud operations with various services such as AWS and DigitalOcean.',
	url='https://www.github.com/pmp47/Cloud',
	author='pmp47',
	author_email='phil@zeural.com',
	license='MIT',
	packages=['cloud'],
	install_requires=['boto3==1.9.220','botocore==1.12.220','dictableobject @ git+https://github.com/pmp47/DictableObject@master#egg=DictableObject==1.1.1','security @ git+https://github.com/pmp47/Security@master#egg=Security==1.1.15','paramiko==3.4.0','python-digitalocean==1.14.0'],
	zip_safe=False,
	include_package_data=True,
	python_requires='>=3.6',

	package_data={'': ['data/*.*']}
)
