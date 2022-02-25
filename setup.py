from setuptools import setup
import subprocess


setup(
    name="irmin",
    version="0.3.1b0",
    description="Irmin bindings for Python",
    author="Zach Shipko",
    author_email="zachshipko@gmail.com",
    url="https://github.com/mirage/irmin-py",
    packages=["irmin"],
    install_requires=["cffi>=1.0.0"],
)
