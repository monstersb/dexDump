#! /usr/bin/env python
#! -*- coding:utf-8 -*-

import sys

from utils import *

from dex import DexFile

dex = DexFile(readfile(sys.argv[1]))
dex.show()
