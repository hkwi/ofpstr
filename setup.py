try:
	from setuptools import setup
except:
	from distutils.core import setup

setup(name='ofpstr',
	version='0.1.2',
	description='Openflow stringer library',
	author='Hiroaki Kawai',
	author_email='hiroaki.kawai@gmail.com',
	url='https://github.com/hkwi/ofpstr/',
	packages=['ofpstr']
)
