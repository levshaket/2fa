# python version:	3
# module name:		cutils
# description:		common utilities for python3
# common usage: 	import cutils as cu


import os, pickle


def save(python_object, filename, directory='.'):
	file_ = os.path.join(directory,filename)
	with open(file_,'wb') as f:
		pickle.dump(python_object, f)

def load(filename, directory='.'):
	file_ = os.path.join(directory, filename)
	with open(file_,'rb') as f:
		python_object = pickle.load(f)
	return python_object
