from setuptools import find_packages, setup

setup(
    name='mutualauth',
    version='0.1',
    description='Mutual TLS authentication for Falcon',
    author='Rackspace',
    author_email='',
    url='',
    license='Apache 2.0',
    packages=[''],
    install_requires=[
        'falcon',
        'structlog',
        'twisted',
    ],
)
