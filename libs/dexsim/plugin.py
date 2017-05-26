# coding:utf-8
'''
    插件的功能：

    1. 根据正则表达式匹配，需要解密的区域
    2. 将代码区解析为，类、方法、参数
    [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
    3. 生成json格式，增加区域ID(Hash)

'''

from json import JSONEncoder
import tempfile
import os
import hashlib
import re


class Plugin(object):
    name = 'Plugin'
    description = ''
    version = ''

    # const/16 v2, 0x1a
    CONST_NUMBER = 'const(?:\/\d+) [vp]\d+, (-?0x[a-f\d]+)\s+'
    # ESCAPE_STRING = '''"(.*?)(?<!\\\\)"'''
    ESCAPE_STRING = '''"(.*?)"'''
    # const-string v3, "encode string"
    CONST_STRING = 'const-string [vp]\d+, ' + ESCAPE_STRING + '.*'
    # move-result-object v0
    MOVE_RESULT_OBJECT = 'move-result-object ([vp]\d+)'
    # new-array v1, v1, [B
    NEW_BYTE_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[B\s+'
    # new-array v1, v1, [B
    NEW_INT_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[I\s+'
    # new-array v1, v1, [B
    NEW_CHAR_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[C\s+'
    # fill-array-data v1, :array_4e
    FILL_ARRAY_DATA = 'fill-array-data [vp]\d+, :array_[\w\d]+\s+'

    #sput-object v0, Lcom/mopub/IkugPWKWxdXGRvZoacqSF;->JSCRIPT:[B
    SPUT_OBJECT = 'sput-object (?P<varname>[vp]\d+), (?P<clsname>L[\w\/\d;]+)->(?P<fieldname>[\w\d]+):(?P<fieldtype>[\[\/\w\d]+)'

    #sget-object v1, Lcom/mopub/IkugPWKWxdXGRvZoacqSF;->JSCRIPT:[B
    SGET_OBJECT = 'sget-object (?P<varname>[vp]\d+), (?P<clsname>L[\w\/\d;]+)->(?P<fieldname>[\w\d]+):(?P<fieldtype>[\[\/\w\d]+)'

    #can be optminized
    INVOKE_STATIC_NORMAL = 'invoke-static.*?{(?P<paramsname>.*?)}, (?P<staticclsname>.*?);->(?P<mtdname>.*?)\((?P<paramstype>.*?)\)Ljava/lang/String;'

    # 保存需要解密的类名、方法、参数 [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
    json_list = []
    # 目标上下文，解密后用于替换
    target_contexts = {}


    def get_invoke_pattern(self, args):
        '''
            根据参数，生成对应invoke-static语句的正则表达式(RE)
        '''
        return r'invoke-static[/\s\w]+\{[vp,\d\s\.]+},\s+([^;]+);->([^\(]+\(%s\))Ljava/lang/String;\s+' % args

    def get_class_name(self, line):
        start = line.index('}, L')
        end = line.index(';->')
        return line[start + 4:end].replace('/', '.')

    def get_method_name(self, line):
        end = line.index(';->')
        args_index = line.index('(')
        return line[end + 3:args_index]

    def get_clz_mtd_name(self, line):
        clz_name, mtd_name = re.search('invoke-static.*?{.*?}, (.*?);->(.*?)\(.*?\)Ljava/lang/String;', line).groups()
        clz_name = clz_name[1:].replace('/', '.')
        return (clz_name, mtd_name)

    def get_clz_mtd_rtn_name(self, line):
        '''
            class_name, method_name, return_variable_name
        '''
        clz_name, mtd_name = re.search('invoke-static.*?{.*?}, (.*?);->(.*?)\(.*?\)Ljava/lang/String;', line).groups()
        clz_name = clz_name[1:].replace('/', '.')

        prog = re.compile(self.MOVE_RESULT_OBJECT)
        mro_statement = prog.search(line).group()
        rtn_name = mro_statement[mro_statement.rindex(' ') + 1:]
        return (clz_name, mtd_name, rtn_name)

    def get_arguments(self, mtd_body, line, proto):
        '''
            获取参数
        '''
        args = []
        if proto == '[B':
            ptn1 = re.compile(':array_[\w\d]+')
            array_data_name = ptn1.search(line).group()
            ptn2 = re.compile('\s+' + array_data_name + '\s+.array-data 1\s+' + '[\w\s]+' + '.end array-data')

            result = ptn2.search(mtd_body)
            if result:
                array_data_context = result.group()
                byte_arr = []
                for item in array_data_context.split()[3:-2]:
                    byte_arr.append(eval(item[:-1]))
                args.append(proto + ':' + str(byte_arr))
        elif proto == '[I':
            ptn1 = re.compile(':array_[\w\d]+')
            array_data_name = ptn1.search(line).group()
            ptn2 = re.compile('\s+' + array_data_name + '\s+.array-data \d\s+' + '[-\w\s]+' + '.end array-data')

            result = ptn2.search(mtd_body)
            if result:
                array_data_context = result.group()
                byte_arr = []
                for item in array_data_context.split()[3:-2]:
                    byte_arr.append(eval(item))
                args.append(proto + ':' + str(byte_arr))
        elif proto == 'java.lang.String':
            const_str = re.findall("\".+", line)[-1]
            arg1 = []
            for item in const_str[1:-1].encode("UTF-8"):
                arg1.append(item)
            args.append("java.lang.String:" + str(arg1))
        elif proto in ['I', 'II', 'III']:
            prog2 = re.compile(self.CONST_NUMBER)
            args = []
            for item in prog2.finditer(line):
                cn = item.group().split(", ")
                args.append('I:' + str(eval(cn[1].strip())))
        return args

    def get_array_data(self, array_data_name, mtd_body):
        '''
            @:param array_data_name looks like ":array_le" or "fill-array-data v0, :array_1e"

            @:return {'eleLength':eleLength, 'eleType':eleType, 'arraydata':arraydata}
                    eleLength will like 1, 4, 8
                    eleType will like B, I, J, D, etc   (or byte, int, long, double, float)
                    ary will be the [ele1, ele2, ..]

            private byte [] bAry = new byte[] {104, 116, 116, };
            private int [] intAry = new int[] {6874, 43, 390};
            private  double [] doubleAry = new double [] {5.0, 4.2, 3.0, 1.1};
            private long [] lAry = new long[] {112, 115, 46, 99, 111, 109, 47, 115};

            .line 7
            const/16 v0, 0x1a
            new-array v0, v0, [B
            fill-array-data v0, :array_26
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->bAry:[B

            .line 9
            const/4 v0, 0x3
            new-array v0, v0, [I
            fill-array-data v0, :array_38
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->intAry:[I

            .line 10
            const/4 v0, 0x4
            new-array v0, v0, [D
            fill-array-data v0, :array_42
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->doubleAry:[D

            .line 11
            const/16 v0, 0x8
            new-array v0, v0, [J
            fill-array-data v0, :array_56
            iput-object v0, p0, Lcom/example/xx/arytype/AryType;->lAry:[J

            .line 7
            :array_26
            .array-data 1           #this is the [B  case, 1 indicate its length
                0x68t               # indicate its type
                0x74t
                ...
            .end array-data

            .line 9
            :array_38
            .array-data 4          #this is the [I case, 4 indicate its length
                0x1ada             # indicate its type
                0x2b
                0x186
            .end array-data

            .line 10
            :array_42
            .array-data 8           #this is the double Ary case, its length and type
                0x4014000000000000L    # 5.0
                0x4010cccccccccccdL    # 4.2
                0x4008000000000000L    # 3.0
                0x3ff199999999999aL    # 1.1
            .end array-data

            .line 11
            :array_56
            .array-data 8           #this is the [J   long type, 8 indicate ites length
                0x70                #
                0x73
            .end array-data
        '''
        array_data_name = ''.join(array_data_name.split("\n")[0].partition(':')[1:])
        pattern = array_data_name + '\s+.array-data (?P<eleLength>\d+)\s+' + '(?P<lines>.*?)' + '.end array-data'
        prog = re.compile(pattern, re.DOTALL) #make . can match newline
        mObj = prog.search(mtd_body)

        eleLength = mObj.group('eleLength')
        eleType = ''
        arraydata = []

        prog_data = re.compile('(?P<value>.*?0x[0-9a-f]+)(?P<type>\w?)')
        lines = mObj.group('lines')
        for line in lines.split('\n'):
            #0x4010cccccccccccdL    # 4.2
            try:
                data = line.strip().split()[0]
            except:
                continue
            m = prog_data.search(data)
            eleType = m.group('type')
            arraydata.append(eval(m.group('value')))

        return {'eleLength':eleLength, 'eleType':eleType, 'arraydata':arraydata}

    def get_return_variable_name(self, line):
        p3 = re.compile(self.MOVE_RESULT_OBJECT)
        mro_statement = p3.search(line).group()
        return mro_statement[mro_statement.rindex(' ') + 1:]

    def get_json_item(self, cls_name, mtd_name, args):
        '''
            生产解密目标
        '''
        item = {'className': cls_name, 'methodName': mtd_name, 'arguments': args}
        ID = hashlib.sha256(JSONEncoder().encode(item).encode('utf-8')).hexdigest()
        item['id'] = ID
        return item


    def append_json_item(self, json_item, mtd, line, return_variable_name):
        '''
            添加到json_list, target_contexts
        '''
        mid = json_item['id']
        if mid not in self.target_contexts.keys():
            self.target_contexts[mid] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
        else:
            self.target_contexts[mid].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

        if json_item not in self.json_list:
            self.json_list.append(json_item)


    def __init__(self, driver, methods, smali_files):
        self.make_changes = False
        self.driver = driver
        self.methods = methods
        self.smali_files = smali_files

    def run(self):
        '''
            匹配代码，生成指定格式的文件(包含类名、方法、参数)
        '''
        pass

    def optimize(self):
        '''
            重复的代码，考虑去除
            生成json
            生成驱动解密
            更新内存
            写入文件
        '''
        if not self.json_list or not self.target_contexts:
            return

        jsons = JSONEncoder().encode(self.json_list)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as fp:
            fp.write(jsons)
        outputs = self.driver.decode(fp.name)
        os.unlink(fp.name)

        # 替换内存
        # output 存放的是解密后的结果。
        for key in outputs:
            if 'success' in outputs[key]:
                if key not in self.target_contexts.keys():
                    print('not found', key)
                    continue
                for item in self.target_contexts[key]:
                    old_body = item[0].body
                    target_context = item[1]
                    new_context = item[2] + outputs[key][1]

                    # It's not a string.
                    if 'null' == outputs[key][1]:
                        continue
                    print('found sth: ', outputs[key][1])
                    item[0].body = old_body.replace(target_context, new_context)
                    item[0].modified = True
                    self.make_changes = True

        self.smali_files_update()

    def optimizations(self, json_list, target_contexts):
        '''
            重复的代码，考虑去除
            生成json
            生成驱动解密
            更新内存
            写入文件
        '''
        if not json_list or not target_contexts:
            return

        jsons = JSONEncoder().encode(json_list)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as fp:
            fp.write(jsons)
        outputs = self.driver.decode(fp.name)
        os.unlink(fp.name)

        # print(outputs)

        # 替换内存
        # output 存放的是解密后的结果。
        for key in outputs:
            if 'success' in outputs[key]:
                if key not in target_contexts.keys():
                    print('not found', key)
                    continue
                for item in target_contexts[key]:
                    old_body = item[0].body
                    target_context = item[1]
                    new_context = item[2] + outputs[key][1]

                    # It's not a string.
                    if 'null' == outputs[key][1]:
                        continue
                    print('found sth: ', outputs[key][1])
                    item[0].body = old_body.replace(target_context, new_context)
                    item[0].modified = True
                    self.make_changes = True

        self.smali_files_update()

    def smali_files_update(self):
        '''
            write changes to smali files
        '''
        if self.make_changes:
            for smali_file in self.smali_files:
                smali_file.update()
