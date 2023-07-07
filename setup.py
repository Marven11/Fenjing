import setuptools
import os

with open("README.md", "r") as f:
    long_description = f.read()

with open("VERSION", "r") as f:
    version = f.read().strip()

with open("requirements.txt", "r") as f:
    requirements = [
        line.strip() for line in f.readlines()
    ]

setuptools.setup(
    name="fenjing",
    version=version,
    author="Marven11",
    author_email="marven11@example.com",
    description="A Jinja SSTI cracker for CTF competitions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Marven11/Fenjing",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements,
    package_data={
        "fenjing": ["templates/*", "static/*"],
    },
)
