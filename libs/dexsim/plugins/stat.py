# coding:utf-8

import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin
from collections import defaultdict


__all__ = ["STAT"]


class STAT(Plugin):
    '''
    do some basic statistics info:
    1) how many decode-method involved  ( invoke-static method(paramsType)String)
    2)
    '''

    name = "STAT"
    version = '0.0.3'

    stat_info = defaultdict(int)
    flg = False

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        if STAT.flg:
            return
        print('run Plugin: %s' % self.name, end=' -> ')
        self._process()
        self.show()

    def get_func_info(self, line):
        '''
        :param line:  contains the invoke-static method

        :return:
        '''
        # 'invoke-static.*?{(?P<paramsname>.*?)}, (?P<staticclsname>.*?);->(?P<mtdname>.*?)\((?P<paramstype>.*?)\)Ljava/lang/String;'
        prog = re.compile(self.INVOKE_STATIC_NORMAL)
        m = prog.search(line)

        ret = {'paramsname':'', 'staticclsname':'', 'mtdname':'', 'paramstype':''}
        try:
            return(m.groupdict())
        except:
            return(ret)

    def _process(self):
        p = re.compile(self.INVOKE_STATIC_NORMAL)

        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                block = i.group()

                funcInfo = self.get_func_info(block)
                if not funcInfo['paramsname']:
                    continue

                method = ('%s->%s(%s)'%(funcInfo['staticclsname'], funcInfo['mtdname'], funcInfo['paramstype']), funcInfo['paramstype'])
                STAT.stat_info[method] += 1

    def show(self):
        if STAT.flg:
            return

        STAT.flg = True
        print('\n\n----stat-info-----\n')

        for mtd in sorted(STAT.stat_info, key=lambda item: STAT.stat_info[item], reverse=True):
            print('%s\t%d'%('\t'.join(mtd), STAT.stat_info[mtd]))

