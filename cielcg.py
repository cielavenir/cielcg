#!/usr/bin/python

'''
cielcg - alternative cgroup-tools (cgexec) implementation for both cgroup v1 and v2 (cgroup2)

(C) @cielavenir

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import sys
import os
import argparse
import shutil
import errno

try:
    from shutil import chown
except ImportError:
    from backports.shutil_chown import chown

cgrpath = cgrver = None
def GetCgroupMount():
    global cgrpath, cgrver
    if cgrpath:
        return (cgrpath, cgrver)
    with open('/proc/mounts') as f:
        for line in f:
            dv, path, typ, opt, x, y = line.rstrip().split()
            if typ == 'cgroup':
                cgrpath, cgrver = os.path.dirname(path), 1
                return (cgrpath, cgrver)
        f.seek(0)
        for line in f:
            dv, path, typ, opt, x, y = line.rstrip().split()
            if typ == 'cgroup2':
                cgrpath, cgrver = path, 2
                return (cgrpath, cgrver)
    raise Exception('could not found cgroup path')

def ConvertToInt(val):
    try:
        return int(val)
    except ValueError:
        return val

def makedirs(name, mode=0o777, exist_ok=False):
    if not exist_ok:
        os.makedirs(name,mode=mode)
    elif sys.version_info[0]>=3:
        os.makedirs(name,mode=mode,exist_ok=exist_ok)
    else:
        try:
            os.makedirs(name,mode=mode)
        except OSError as e:
            if e.errno!=errno.EEXIST:
                raise

def rmdirs(path):
    for curDir, dirs, files in os.walk(path, topdown=False):
        for dir in dirs:
            if not os.path.islink(os.path.join(curDir, dir)):
                os.rmdir(os.path.join(curDir, dir))
    os.rmdir(path)

def cgexec(logout, argv):
    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='cgexec')
    parser.add_argument('-g', action='append', default=[], metavar='<controllers>:<path>', help='Control group which should be added')
    parser.add_argument('cmd', nargs=argparse.REMAINDER, help='Command to execute')
    args = parser.parse_args(argv)
    # print(args.cmd)

    if not args.cmd:
        sys.stderr.write('command to execute is not specified\n')
        return

    pid = os.getpid()
    if cgrver == 1:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            with open(os.path.join(cgrpath,typ,path,'cgroup.procs'), 'a') as f:
                f.write('%d\n'%pid)
    elif cgrver == 2:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            with open(os.path.join(cgrpath,path,'cgroup.procs'), 'a') as f:
                f.write('%d\n'%pid)
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)
    os.execvp(args.cmd[0],args.cmd)

def cgset(logout, argv):
    def cgr2write(dir, key, val):
        if key == 'cpu.cfs_period_us':
            if os.path.isfile(os.path.join(dir,'cpu.max')):
                with open(os.path.join(dir,'cpu.max'), 'r+') as f:
                    cont = f.read().split()
                    cont[1] = val
                    f.seek(0)
                    f.write('%s\n'%(' '.join(cont)))
                    f.truncate(f.tell())
                return True
            return False
        if key == 'cpu.cfs_quota_us':
            if os.path.isfile(os.path.join(dir,'cpu.max')):
                with open(os.path.join(dir,'cpu.max'), 'r+') as f:
                    cont = f.read().split()
                    cont[0] = 'max' if val=='-1' else val
                    f.seek(0)
                    f.write('%s\n'%(' '.join(cont)))
                    f.truncate(f.tell())
                return True
            return False
        if key == 'cpu.rt_period_us':
            if os.path.isfile(os.path.join(dir,'cpu.rt.max')):
                with open(os.path.join(dir,'cpu.rt.max'), 'r+') as f:
                    cont = f.read().split()
                    cont[1] = val
                    f.seek(0)
                    f.write('%s\n'%(' '.join(cont)))
                    f.truncate(f.tell())
                return True
            return False
        if key == 'cpu.rt_runtime_us':
            if os.path.isfile(os.path.join(dir,'cpu.rt.max')):
                with open(os.path.join(dir,'cpu.rt.max'), 'r+') as f:
                    cont = f.read().split()
                    cont[0] = 'max' if val=='-1' else val
                    f.seek(0)
                    f.write('%s\n'%(' '.join(cont)))
                    f.truncate(f.tell())
                return True
            return False
        elif key == 'cpu.shares':
            if os.path.isfile(os.path.join(dir,'cpu.weight')):
                with open(os.path.join(dir,'cpu.weight'), 'w') as f:
                    f.write('%d\n'%(int(val) * 100 // 1024))
                return True
            return False
        elif key == 'memory.limit_in_bytes':
            if os.path.isfile(os.path.join(dir,'memory.max')):
                with open(os.path.join(dir,'memory.max'), 'w') as f:
                    f.write('%s\n'%val) # todo handle max properly
                return True
            return False
        elif key == 'memory.soft_limit_in_bytes':
            if os.path.isfile(os.path.join(dir,'memory.high')):
                with open(os.path.join(dir,'memory.high'), 'w') as f:
                    f.write('%s\n'%val) # todo handle max properly
                return True
            return False

    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='cgset')
    parser.add_argument('-r', '--variable', metavar='<name=value>', action='append', default=[], help='Define parameter to set')
    parser.add_argument('--copy-from', metavar='<source_cgroup_path>', help='Control group whose parameters will be copied')
    parser.add_argument('path', nargs='+', help='Control group')
    args = parser.parse_args(argv)

    if args.copy_from is None and not args.variable:
        sys.stderr.write('need to parameter value or source\n')
        return

    if cgrver == 1:
        for path in args.path:
            if path.startswith('/'):
                path = path[1:]
            if args.copy_from is not None:
                src = args.copy_from
                if src.startswith('/'):
                    src = src[1:]
                for typ in [e for e in os.listdir(cgrpath) if not os.path.islink(os.path.join(cgrpath,e))]:
                    if os.path.isdir(os.path.join(cgrpath,typ,src)) and os.path.isdir(os.path.join(cgrpath,typ,path)):
                        for ent in os.listdir(os.path.join(cgrpath,typ,src)):
                            if os.path.isfile(os.path.join(cgrpath,typ,src,ent)):
                                if ent in ['tasks', 'notify_on_release', 'release_agent']:
                                    continue
                                if ent.startswith('cgroup.'):
                                    continue
                                with open(os.path.join(cgrpath,typ,src,ent), 'r') as fin:
                                    try:
                                        with open(os.path.join(cgrpath,typ,path,ent), 'w') as fout:
                                            shutil.copyfileobj(fin, fout)
                                    except OSError as e:
                                        if e.errno!=errno.EINVAL:
                                            raise
            for var in args.variable:
                key, val = var.split('=',1)
                typ = key.split('.')[0]
                with open(os.path.join(cgrpath,typ,path,key), 'w') as f:
                    f.write(val)
    elif cgrver == 2:
        for path in args.path:
            if path.startswith('/'):
                path = path[1:]
            if args.copy_from is not None:
                src = args.copy_from
                if src.startswith('/'):
                    src = src[1:]
                for ent in os.listdir(os.path.join(cgrpath,src)):
                    if os.path.isfile(os.path.join(cgrpath,src,ent)):
                        if ent.startswith('cgroup.'):
                            continue
                        with open(os.path.join(cgrpath,src,ent), 'r') as fin:
                            try:
                                with open(os.path.join(cgrpath,path,ent), 'w') as fout:
                                    shutil.copyfileobj(fin, fout)
                            except OSError as e:
                                if e.errno!=errno.EINVAL:
                                    raise
            for var in args.variable:
                key, val = var.split('=',1)
                if not cgr2write(os.path.join(cgrpath,path), key, val):
                    with open(os.path.join(cgrpath,path,key), 'w') as f:
                        f.write(val)
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def cgget(logout, argv):
    def cgr2read(logout, args, dir, key):
        if key == 'cpu.cfs_period_us':
            if os.path.isfile(os.path.join(dir,'cpu.max')):
                with open(os.path.join(dir,'cpu.max'), 'r') as f:
                    cont = f.read().split()[1]
                if not args.values_only:
                    logout.write('cpu.cfs_period_us: ')
                logout.write('%s\n'%cont)
                return True
            return False
        elif key == 'cpu.cfs_quota_us':
            if os.path.isfile(os.path.join(dir,'cpu.max')):
                with open(os.path.join(dir,'cpu.max'), 'r') as f:
                    cont = f.read().split()[0]
                if not args.values_only:
                    logout.write('cpu.cfs_quota_us: ')
                logout.write('%s\n'%('-1' if cont == 'max' else cont))
                return True
            return False
        elif key == 'cpu.rt_period_us':
            if os.path.isfile(os.path.join(dir,'cpu.rt.max')):
                with open(os.path.join(dir,'cpu.rt.max'), 'r') as f:
                    cont = f.read().split()[1]
                if not args.values_only:
                    logout.write('cpu.rt_period_us: ')
                logout.write('%s\n'%cont)
                return True
            return False
        elif key == 'cpu.rt_runtime_us':
            if os.path.isfile(os.path.join(dir,'cpu.rt.max')):
                with open(os.path.join(dir,'cpu.rt.max'), 'r') as f:
                    cont = f.read().split()[0]
                if not args.values_only:
                    logout.write('cpu.rt_runtime_us: ')
                logout.write('%s\n'%('-1' if cont == 'max' else cont))
                return True
            return False
        elif key == 'cpu.shares':
            if os.path.isfile(os.path.join(dir,'cpu.weight')):
                with open(os.path.join(dir,'cpu.weight'), 'r') as f:
                    cont = int(f.read())
                if not args.values_only:
                    logout.write('cpu.shares: ')
                logout.write('%d\n'%(1024 * cont // 100))
                return True
            return False
        elif key == 'memory.limit_in_bytes':
            if os.path.isfile(os.path.join(dir,'memory.max')):
                with open(os.path.join(dir,'memory.max'), 'r') as f:
                    cont = f.read().strip()
                if not args.values_only:
                    logout.write('memory.limit_in_bytes: ')
                logout.write('%s\n'%(str((1<<63)-4096) if cont == 'max' else cont))
                return True
            return False
        elif key == 'memory.soft_limit_in_bytes':
            if os.path.isfile(os.path.join(dir,'memory.high')):
                with open(os.path.join(dir,'memory.high'), 'r') as f:
                    cont = f.read().strip()
                if not args.values_only:
                    logout.write('memory.soft_limit_in_bytes: ')
                logout.write('%s\n'%(str((1<<63)-4096) if cont == 'max' else cont))
                return True
            return False

    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='cgget')
    parser.add_argument('-g', action='append', default=[], metavar='<controllers>(:<path>)', help='Control group which should be added')
    parser.add_argument('-r', '--variable', metavar='<name>', action='append', default=[], help='Define parameter to display')
    parser.add_argument('-n', action='store_true', help='Do not print headers')
    parser.add_argument('-v', '--values-only', action='store_true', help='Print only values, not parameter names')
    parser.add_argument('path', nargs='*', help='Control group')
    args = parser.parse_args(argv)

    paths = []
    for path in args.path:
        paths.append(path)
    typs = []
    for grp in args.g:
        typpath = grp.split(':')
        if len(typpath)==1:
            typs.append(typpath[0])
    if not typs and cgrver == 1:
        typs = [e for e in os.listdir(cgrpath) if not os.path.islink(os.path.join(cgrpath,e))]

    if cgrver == 1:
        for path in args.path:
            if not args.n:
                logout.write('%s:\n'%path)
            if path.startswith('/'):
                path = path[1:]
            for typ in typs:
                if os.path.isdir(os.path.join(cgrpath,typ,path)):
                    for ent in sorted(os.listdir(os.path.join(cgrpath,typ,path))):
                        if not os.path.isfile(os.path.join(cgrpath,typ,path,ent)):
                            continue
                        if ent in ['tasks', 'notify_on_release', 'release_agent']:
                            continue
                        if ent.startswith('cgroup.'):
                            continue
                        if args.variable and ent not in args.variable:
                            continue
                        if not args.values_only:
                            logout.write('%s: '%ent)
                        if not os.stat(os.path.join(cgrpath,typ,path,ent)).st_mode&0o400:
                            logout.write('\n')
                            continue
                        with open(os.path.join(cgrpath,typ,path,ent), 'r') as f:
                            shutil.copyfileobj(f, logout)
        for grp in args.g:
            typpath = grp.split(':')
            if len(typpath)==2:
                typ, path = typpath
                if not args.n:
                    logout.write('%s:\n'%path)
                if path.startswith('/'):
                    path = path[1:]
                if os.path.isdir(os.path.join(cgrpath,typ,path)):
                    for ent in sorted(os.listdir(os.path.join(cgrpath,typ,path))):
                        if not os.path.isfile(os.path.join(cgrpath,typ,path,ent)):
                            continue
                        if ent in ['tasks', 'notify_on_release', 'release_agent']:
                            continue
                        if ent.startswith('cgroup.'):
                            continue
                        if args.variable and ent not in args.variable:
                            continue
                        if not args.values_only:
                            logout.write('%s: '%ent)
                        if not os.stat(os.path.join(cgrpath,typ,path,ent)).st_mode&0o400:
                            logout.write('\n')
                            continue
                        with open(os.path.join(cgrpath,typ,path,ent), 'r') as f:
                            shutil.copyfileobj(f, logout)
    elif cgrver == 2:
        for path in args.path:
            if not args.n:
                logout.write('%s:\n'%path)
            if path.startswith('/'):
                path = path[1:]
            if 1:
                if os.path.isdir(os.path.join(cgrpath,path)):
                    for ent in args.variable:
                        cgr2read(logout, args, os.path.join(cgrpath,path), ent)
                    for ent in sorted(os.listdir(os.path.join(cgrpath,path))):
                        if not os.path.isfile(os.path.join(cgrpath,path,ent)):
                            continue
                        if ent.startswith('cgroup.'):
                            continue
                        if args.variable and ent not in args.variable:
                            continue
                        if not args.values_only:
                            logout.write('%s: '%ent)
                        if not os.stat(os.path.join(cgrpath,path,ent)).st_mode&0o400:
                            logout.write('\n')
                            continue
                        with open(os.path.join(cgrpath,path,ent), 'r') as f:
                            shutil.copyfileobj(f, logout)
        for grp in args.g:
            typpath = grp.split(':')
            if len(typpath)==2:
                typ, path = typpath
                if not args.n:
                    logout.write('%s:\n'%path)
                if path.startswith('/'):
                    path = path[1:]
                if os.path.isdir(os.path.join(cgrpath,path)):
                    for ent in args.variable:
                        cgr2read(logout, args, os.path.join(cgrpath,path), ent)
                    for ent in sorted(os.listdir(os.path.join(cgrpath,path))):
                        if not os.path.isfile(os.path.join(cgrpath,path,ent)):
                            continue
                        if not ent.startswith(typ+'.'):
                            continue
                        if ent.startswith('cgroup.'):
                            continue
                        if args.variable and ent not in args.variable:
                            continue
                        if not args.values_only:
                            logout.write('%s: '%ent)
                        if not os.stat(os.path.join(cgrpath,path,ent)).st_mode&0o400:
                            logout.write('\n')
                            continue
                        with open(os.path.join(cgrpath,path,ent), 'r') as f:
                            shutil.copyfileobj(f, logout)
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def cgcreate(logout, argv):
    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='cgcreate')
    parser.add_argument('-g', action='append', required=True, default=[], metavar='<controllers>:<path>', help='Control group which should be added')
    parser.add_argument('-a', metavar='<tuid>:<tgid>', help='Owner of the group and all its files')
    parser.add_argument('-t', metavar='<tuid>:<tgid>', help='Owner of the tasks file')
    parser.add_argument('-s', '--tperm', metavar='mode', help='Tasks file permissions')
    # parser.add_argument('-d', '--dperm', metavar='mode', help='Group directory permissions')
    # parser.add_argument('-f', '--fperm', metavar='mode', help='Group file permissions')
    args = parser.parse_args(argv)

    if cgrver == 1:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            makedirs(os.path.join(cgrpath,typ,path),0o755,exist_ok=True)
            if args.a is not None:
                uid, gid = args.a.split(':')
                chown(os.path.join(cgrpath,typ,path), ConvertToInt(uid), ConvertToInt(gid)) 
            if args.t is not None:
                uid, gid = args.t.split(':')
                chown(os.path.join(cgrpath,typ,path,'tasks'), ConvertToInt(uid), ConvertToInt(gid))
                chown(os.path.join(cgrpath,typ,path,'cgroup.procs'), ConvertToInt(uid), ConvertToInt(gid))
            if args.tperm is not None:
                os.chmod(os.path.join(cgrpath,typ,path,'tasks'), int(args.tperm, 8))
                os.chmod(os.path.join(cgrpath,typ,path,'cgroup.procs'), int(args.tperm, 8))
    elif cgrver == 2:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            makedirs(os.path.join(cgrpath,path),0o755,exist_ok=True)
            if args.a is not None:
                uid, gid = args.a.split(':')
                chown(os.path.join(cgrpath,path), ConvertToInt(uid), ConvertToInt(gid))
            if args.t is not None:
                uid, gid = args.t.split(':')
                chown(os.path.join(cgrpath,path,'cgroup.procs'), ConvertToInt(uid), ConvertToInt(gid))
            if args.tperm is not None:
                os.chmod(os.path.join(cgrpath,typ,path,'cgroup.procs'), int(args.tperm, 8))
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def cgdelete(logout, argv):
    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='cgdelete')
    parser.add_argument('-g', action='append', required=True, default=[], metavar='<controllers>:<path>', help='Control group to be removed')
    parser.add_argument('-r', action='store_true', help='Recursively remove all subgroups')
    args = parser.parse_args(argv)

    if cgrver == 1:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            if os.path.isdir(os.path.join(cgrpath,typ,path)):
                if args.r:
                    rmdirs(os.path.join(cgrpath,typ,path))
                else:
                    os.rmdir(os.path.join(cgrpath,typ,path))
    elif cgrver == 2:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            if os.path.isdir(os.path.join(cgrpath,path)):
                if args.r:
                    rmdirs(os.path.join(cgrpath,path))
                else:
                    os.rmdir(os.path.join(cgrpath,path))
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def cgclassify(logout, argv):
    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='cgclassify')
    parser.add_argument('-g', action='append', default=[], metavar='<controllers>:<path>', help='Control group to be used as target')
    parser.add_argument('pids', nargs='+', type=int, help='PIDs to set cgroup')
    args = parser.parse_args(argv)

    if cgrver == 1:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            with open(os.path.join(cgrpath,typ,path,'tasks'), 'a') as f:
                for pid in args.pids:
                    f.write('%d\n'%pid)
    elif cgrver == 2:
        for grp in args.g:
            typ, path = grp.split(':')
            if typ.startswith('/'):
                typ = typ[1:]
            if path.startswith('/'):
                path = path[1:]
            with open(os.path.join(cgrpath,path,'tasks'), 'a') as f:
                for pid in args.pids:
                    f.write('%d\n'%pid)
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def lssubsys(logout, argv):
    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='lssubsys')
    args = parser.parse_args(argv)

    if cgrver == 1:
        for typ in sorted(os.listdir(cgrpath)):
            if os.path.isdir(os.path.join(cgrpath,typ)) and not os.path.islink(os.path.join(cgrpath,typ)):
                logout.write('%s\n'%typ)
    elif cgrver == 2:
        pass
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def lscgroup(logout, argv):
    cgrpath, cgrver = GetCgroupMount()
    parser = argparse.ArgumentParser(prog='lscgroup')
    args = parser.parse_args(argv)

    if cgrver == 1:
        for typ in sorted(os.listdir(cgrpath)):
            if os.path.isdir(os.path.join(cgrpath,typ)) and not os.path.islink(os.path.join(cgrpath,typ)):
                for curDir, dirs, files in os.walk(os.path.join(cgrpath,typ)):
                    for dir in dirs:
                        logout.write('%s:%s\n'%(typ,os.path.join(curDir,dir)[len(os.path.join(cgrpath,typ)):]))
    elif cgrver == 2:
        for curDir, dirs, files in os.walk(cgrpath):
            for dir in dirs:
                logout.write(':%s\n'%(os.path.join(curDir,dir)[len(cgrpath):]))
    else:
        raise NotImplementedError('unknown cgroup version %d'%cgrver)

def cgsnapshot(logout, argv):
    raise NotImplementedError()

def cgclear(logout, argv):
    raise NotImplementedError()

def cgconfigparser(logout, argv):
    raise NotImplementedError()

def cgrulesengd(logout, argv):
    raise NotImplementedError()

def main(logout, argv):
    appletList = {
        'cgexec':         cgexec,
        'cgset':          cgset,
        'cgget':          cgget,
        'cgcreate':       cgcreate,
        'cgdelete':       cgdelete,
        'cgclassify':     cgclassify,
        'lssubsys':       lssubsys,
        'lscgroup':       lscgroup,
        # 'cgsnapshot':     cgsnapshot,
        # 'cgclear':        cgclear,
        # 'cgconfigparser': cgconfigparser,
        # 'cgrulesengd':    cgrulesengd,
    }
    prog = os.path.basename(argv[0]).split('.')[0]
    if prog not in appletList:
        exe = argv.pop(0)
        if not argv:
            sys.stderr.write('cielcg - alternative cgroup-tools (cgexec) implementation for both cgroup v1 and v2 (cgroup2)')
            sys.stderr.write('use --list to show available subcommands.')
        prog = argv[0]
        if prog == '--install':
            if not os.path.isfile(exe):
                raise Exception('exe (%s) does not exist. called by $PATH?'%exe)
            for appletname in appletList:
                os.symlink(exe, appletname)
            return
        if prog == '--list':
            for appletname in appletList:
                logout.write('%s\n'%appletname)
            return
    fn = appletList.get(prog)
    if fn is None:
        sys.stderr.write('%s applet is not available\n'%prog)
    else:
        fn(logout, argv[1:])

if __name__ == '__main__':
    main(sys.stdout, list(sys.argv))
