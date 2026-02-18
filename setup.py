from setuptools import find_packages, setup

setup(
    name="nodal_sdk",  # Make sure this matches the import name!
    version="0.1.0",
    packages=find_packages(),  # Ensures all submodules are included
    install_requires=[],  # Add dependencies here if needed
)
