from setuptools import find_packages, setup

setup(
    name='falcon-mutualauth',
    version='0.6',
    description='Mutual TLS authentication for Falcon',
    author='Rackspace',
    author_email='',
    url='',
    license='Apache 2.0',
    packages=find_packages(),
    install_requires=[
        'falcon',
        'structlog',
        'twisted',
        'pyopenssl',
        'service_identity',
    ],
)
