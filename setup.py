#! /usr/bin/python3

from distutils.core import setup, Extension

setup(
	name = 'hardhat-python',
	version = '1.0.0',
	ext_modules = [Extension('hardhat', ['hardhat.c'], libraries=['hardhat'])]
)
