from setuptools import setup, find_packages

setup(
    name="changedetectionio_ssl",
    version="0.0.1",
    description="SSL certificate monitoring plugin for changedetection.io",
    author="WebTechnologies S.r.o.",
    author_email="dgtlmoon@gmail.com",
    packages=find_packages(),
    install_requires=[
        "changedetection.io>=0.50.0",
        "pyopenssl>=25.0.0",
        "cryptography>=42.0.0",
    ],
    entry_points={
        "changedetectionio_processors": [
            "ssl_certificate = ssl_plugin:plugin_instance"
        ]
    }
)