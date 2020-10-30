#!/usr/bin/env python3
'''
prov

A Python script to communicate with a Cobbler server's XMLRPC API.
'''
# SEE: https://github.com/cobbler/cobbler/blob/master/cobbler/remote.py

# ------- Python Library Imports -------

# Standard Library
import argparse
import copy
import difflib
import glob
import logging
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import xmlrpc.client

# Additional Dependencies
try:
    import yaml
except ImportError as e:
    sys.exit('Unable to import PyYAML library - ' + str(e) + '.')

# --------------------------------------



# ----------- Initialization -----------

HELP_DESCRIPTION = """
A Python script to enforce declarative Cobbler configurations.
"""

HELP_EPILOG = """
"""

# Color Sequences
C_BLUE   = '\033[94m'
C_BOLD   = '\033[1m'
C_END    = '\033[0m'
C_GREEN  = '\033[92m'
C_ORANGE = '\033[93m'
C_RED    = '\033[91m'

COBBLER_BOOTLOADERS = [
    'grub',
    'ipxe',
    'pxelinux',
    'yaboot'
]

COBBLER_KINDS = [
    'distros',
    'images',
    'mgmtclasses',
    'profiles',
    'repos',
    'systems',
]

# what prov expects -> what cobbler expects
COBBLER_KIND_MAP = {
    'distros': 'distro',
    'images': 'image',
    'mgmtclasses': 'mgmtclass',
    'profiles': 'profile',
    'repos': 'repo',
    'systems': 'system'
}

COBBLER_IGNORED_KEYS = [
    'ctime',
    'depth',
    'ipv6_autoconfiguration',
    'mtime',
    'name',
    'repos_enabled',
    'uid'
]

COBBLER_INTERFACES_IGNORED_KEYS = [
    'ctime',
    'depth',
    'distro',
    'gateway',
    'hostname',
    'ipv6_autoconfiguration',
    'mtime',
    'name',
    'owner',
    'repos_enabled',
    'uid'
]

COBBLER_INTERFACE_TYPES = [
    'bmc',
    'bond',
    'bond_slave',
    'bonded_bridge_slave',
    'bridge',
    'bridge_slave',
    'infiniband',
    'na'
]

COBBLER_REPO_ARCHS = [
    'aarch64',
    'arm',
    'i386',
    'ia64',
    'noarch',
    'ppc',
    'ppc64',
    'ppc64el',
    'ppc64le',
    's390',
    's390x',
    'src',
    'x86_64'
]

COBBLER_REPO_BREEDS = [
    'apt',
    'rhn',
    'rsync',
    'wget',
    'yum'
]

VALID_IPv4_REGEX = re.compile(
    r'^(?:\d{1,3}\.){3}\d{1,3}$'
)

VALID_MAC_REGEX = re.compile(
    r'^(?:[\dA-Fa-f]{2}\:){5}[\dA-Fa-f]{2}$'
)

#---------------------------------------



# --------- Class Definitions ----------

class Cobbler:
    '''
    Represents a connection to a cobbler server.
    '''
    def __init__(self, api_endpoint, password, port, server, ssl, username):
        '''
        Connects to the specified Cobbler server.
        '''
        try:
            self.server = xmlrpc.client.ServerProxy(
                '{http}://{servername}:{port}/{api_endpoint}'.format(
                    http = 'https' if ssl else 'http',
                    servername = server,
                    port = str(port),
                    api_endpoint = api_endpoint
                )
            )
        except Exception as e:
            raise Exception('Unable to establish connection with Cobbler server - ' + str(e))
        try:
            self.token = self.server.login(username, password)
        except Exception as e:
            raise Exception('Unable to authenticate with Cobbler server - ' + str(e))
        try:
            self.api_version = self.server.version()
        except Exception as e:
            raise Exception('Unable to determine Cobbler server API version - ' + str(e))
        try:
            self.data = {}
            self.data['distros'] = self.server.get_distros()
            self.data['images'] = self.server.get_images()
            self.data['mgmtclasses'] = self.server.get_mgmtclasses()
            self.data['profiles'] = self.server.get_profiles()
            self.data['repos'] = self.server.get_repos()
            self.data['systems'] = self.server.get_systems()
        except Exception as e:
            raise Exception('Unable to initialize data cache - ' + str(e))
        try:
            self.server_settings = self.server.get_settings()
        except Exception as e:
            raise Exception('Unable to obtain Cobbler server settings - ' + str(e))
        self.files = {'snippets': {}, 'templates': {}}
        self.valid_distro_archs = []
        self.valid_distro_breeds = {}
        if self.api_version >= 3.0:
            try:
                for snippet in self.server.get_autoinstall_snippets():
                    self.files['snippets'][snippet] = self.server.read_autoinstall_snippet(snippet, self.token)
                for template in self.server.get_autoinstall_templates():
                    self.files['templates'][template] = self.server.read_autoinstall_template(template, self.token)
            except Exception as e:
                raise Exception('Unable to obtain Cobbler autoinstall templates/snippets - ' + str(e))
            try:
                self.valid_distro_archs = self.server.get_valid_archs()
            except Exception as e:
                raise Exception('Unable to obtain valid distribution architectures - ' + str(e))
            try:
                for breed in self.server.get_valid_breeds():
                    self.valid_distro_breeds[breed] = self.server.get_valid_os_versions_for_breed(breed)
            except Exception as e:
                raise Exception('Unable to obtain valid breeds and their corresponding operating system versions - ' + str(e))
        else:
            try:
                server_snippets_dir = self.server_settings.get('snippetsdir', '/var/lib/cobbler/snippets')
                for snippet in self.server.get_snippets():
                    rel_path = os.path.relpath(snippet, server_snippets_dir)
                    self.files['snippets'][rel_path] = self.server.read_or_write_snippet(
                        snippet,
                        True,
                        '',
                        self.token
                    )
                server_templates_dir = os.path.dirname(self.server_settings.get('default_kickstart', '/var/lib/cobbler/kickstarts/default.ks'))
                for template in [t for t in self.server.get_kickstart_templates() if t and t != '<<inherit>>']:
                    rel_path = os.path.relpath(template, server_templates_dir)
                    self.files['templates'][rel_path] = self.server.read_or_write_kickstart_template(
                        template,
                        True,
                        '',
                        self.token
                    )
            except Exception as e:
                raise Exception('Unable to obtain autoinstall templates/snippets (legacy) - ' + str(e))

    def delete(self, kind, name):
        '''
        Deletes the specified cobbler object.

        This function will automatically call `self.legacy_delete()` if the
        Cobbler server version is less than 3.0.
        '''
        if self.api_version < 3.0:
            return self.legacy_delete(kind, name)
        self.server.remove_item(COBBLER_KIND_MAP[kind], name, self.token, False)

    def delete_file(self, kind, path):
        '''
        Deletes the specified file.
        '''
        if self.api_version < 3.0:
            return self.legacy_delete_file(kind, path)
        if kind == 'snippets':
            try:
                self.server.remove_autoinstall_snippet(path, self.token)
            except xmlrpc.client.Fault as e:
                raise Exception(e.faultString)
        elif kind == 'templates':
            try:
                self.server.remove_autoinstall_template(path, self.token)
            except xmlrpc.client.Fault as e:
                raise Exception(e.faultString)

    def legacy_delete_file(self, kind, path):
        '''
        Deletes the specified file (legacy version).

        It turns out that there is no mechanism in Cobbler's XMLRPC API to
        handle this, so we just have to bail.
        '''
        raise Exception('Deletion of files on older Cobbler servers (version < 3.0) is not supported')

    def legacy_delete(self, kind, name):
        '''
        Deletes the specified cobbler object (legacy version).
        '''
        f = self.legacy_get_funcs(kind)
        f['remove'](name, self.token, False)

    def diff(self, kind, name, val):
        '''
        Returns what items would be updated if the specified value were applied.
        Each key is returned with a value as a tuple: (existing, new)
        Dictionaries are flattened.
        '''
        existing = _flatten_dict(self.get(kind, name))
        d = {}
        if existing:
            for k, v in _dict_merge(existing, _flatten_dict(self.prepare(kind, name, val))).items():
                if not k in existing:
                    d[k] = (None, v)
                elif existing[k] != v:
                    d[k] = (existing[k], v)
        return d

    def diff_file(self, kind, path, contents):
        '''
        Returns a file diff associated with the specified file.
        '''
        existing = self.get_file(kind, path)
        if existing and existing != contents:
            return difflib.unified_diff(
                existing.splitlines(keepends=True),
                contents.splitlines(keepends=True),
                fromfile = path,
                tofile = path,
                n = 2
            )
        else:
            return ''

    def dump(self, file_path):
        '''
        Dumps (saves) the current Cobbler server configuration to the specified
        file.
        '''
        converted = {}
        for kind, items in self.data.items():
            converted[kind] = {}
            for i in items:
                if kind == 'systems':
                    converted[kind][i['name']] = {k: v for k,v in i.items() if not k in COBBLER_IGNORED_KEYS and k != 'interfaces'}
                    if 'interfaces' in i:
                        converted[kind][i['name']]['interfaces'] = {}
                        for interface_name, interface_data in i['interfaces'].items():
                            converted[kind][i['name']]['interfaces'][interface_name] = {k: v for k,v in interface_data.items() if not k in COBBLER_INTERFACES_IGNORED_KEYS}
                else:
                    converted[kind][i['name']] = {k: v for k,v in i.items() if not k in COBBLER_IGNORED_KEYS}
        with open(file_path, 'w') as f:
            yaml.dump(converted, f, default_flow_style=False)

    def get(self, kind, name):
        '''
        Obtains the data associated with the specified entry. The function will
        return an empty dictionary if no item is found.
        '''
        try:
            return next(i for i in self.data[kind] if 'name' in i and i['name'] == name)
        except StopIteration:
            return {}


    def get_file(self, kind, path):
        '''
        Obtains the contents of the specified file.

        Returns an empty string if no file was found.
        '''
        return self.files[kind].get(path, '')


    def legacy_get_funcs(self, kind):
        '''
        Returns all of the necessary functions for handling the specified "kind".
        '''
        if not kind in COBBLER_KINDS:
            raise Exception('Specified kind "{k}" is not valid'.format(k=kind))
        if kind == 'distros':
            get_func    = self.server.get_distros
            find_func   = self.server.find_distro
            handle_func = self.server.get_distro_handle
            modify_func = self.server.modify_distro
            new_func    = self.server.new_distro
            remove_func = self.server.remove_distro
            save_func   = self.server.save_distro
        elif kind == 'images':
            get_func    = self.server.get_images
            find_func   = self.server.find_image
            handle_func = self.server.get_image_handle
            modify_func = self.server.modify_image
            new_func    = self.server.new_image
            remove_func = self.server.remove_image
            save_func   = self.server.save_image
        elif kind == 'mgmtclasses':
            get_func    = self.server.get_mgmtclasses
            find_func   = self.server.find_mgmtclass
            handle_func = self.server.get_mgmtclass_handle
            modify_func = self.server.modify_mgmtclass
            new_func    = self.server.new_mgmtclass
            remove_func = self.server.remove_mgmtclass
            save_func   = self.server.save_mgmtclass
        elif kind == 'profiles':
            get_func    = self.server.get_profiles
            find_func   = self.server.find_profile
            handle_func = self.server.get_profile_handle
            modify_func = self.server.modify_profile
            new_func    = self.server.new_profile
            remove_func = self.server.remove_profile
            save_func   = self.server.save_profile
        elif kind == 'repos':
            get_func    = self.server.get_repos
            find_func   = self.server.find_repo
            handle_func = self.server.get_repo_handle
            modify_func = self.server.modify_repo
            new_func    = self.server.new_repo
            remove_func = self.server.remove_repo
            save_func   = self.server.save_repo
        elif kind == 'systems':
            get_func    = self.server.get_systems
            find_func   = self.server.find_system
            handle_func = self.server.get_system_handle
            modify_func = self.server.modify_system
            new_func    = self.server.new_system
            remove_func = self.server.remove_system
            save_func   = self.server.save_system
        return {
            'get': get_func,
            'find': find_func,
            'handle': handle_func,
            'modify': modify_func,
            'new': new_func,
            'remove': remove_func,
            'save': save_func
        }

    def prepare(self, kind, name, val):
        '''
        Prepares an item for injection or comparison.

        Essentially the goal here is that pre v3.0 configs should work for
        Cobbler v3.0+ servers and vice versa.
        '''
        nval = copy.deepcopy(val)
        if self.api_version >= 3.0:
            for k, v in val.items():
                if isinstance(v, str) and v == '~':
                    nval.pop(k)
            if not 'name' in nval:
                nval['name'] = name
            if kind in ['distros', 'profiles', 'systems']:
                if 'kickstart' in nval and nval['kickstart']:
                    nval['autoinstall'] = nval.pop('kickstart')
                if 'ksmeta' in nval and nval['ksmeta']:
                    nval['autoinstall_meta'] = nval.pop('ksmeta')
            if kind == 'distros':
                if not nval['kernel'].startswith('/'):
                    nval['kernel'] = os.path.join('/var/www/cobbler/distro_mirror', nval.pop('kernel'))
                if not nval['initrd'].startswith('/'):
                    nval['initrd'] = os.path.join('/var/www/cobbler/distro_mirror', nval.pop('initrd'))
            if kind == 'repos':
                if not 'environment' in nval:
                    nval['environment'] = {}
                if not 'yumopts' in nval:
                    nval['yumopts'] = {}
        elif self.api_version < 3.0:
            if kind in ['distros', 'profiles', 'systems']:
                if 'autoinstall' in nval and nval['autoinstall']:
                    nval['kickstart'] = nval.pop('autoinstall')
                if 'autoinstall_meta' in nval and nval['autoinstall_meta']:
                    nval['ksmeta'] = nval.pop('autoinstall_meta')
                if 'kickstart' in nval and nval['kickstart'] and nval['kickstart'] != '<<inherit>>':
                    if not nval['kickstart'].startswith('/'):
                        nval['kickstart'] = os.path.join('/var/lib/cobbler/kickstarts', nval['kickstart'])
            if kind == 'distros':
                if 'boot_loader' in nval:
                    nval.pop('boot_loader')
                if not nval['kernel'].startswith('/'):
                    nval['kernel'] = os.path.join('/var/www/cobbler/ks_mirror', nval.pop('kernel'))
                if not nval['initrd'].startswith('/'):
                    nval['initrd'] = os.path.join('/var/www/cobbler/ks_mirror', nval.pop('initrd'))
        if kind in ['distros', 'profiles', 'systems']:
            if 'ks_meta' in nval:
                nval.pop('ks_meta')
        return nval

    def set(self, kind, name, val):
        '''
        Updates the cobbler server with the values from `val`.
        This function assumes that `val` has already been merged with the
        existing data.

        This version uses `xapi_object_edit()` under the hood if the server API
        version is >= 3.0 and calls `self.legacy_set()` otherwise.
        '''
        if self.api_version < 3.0:
            return self.legacy_set(kind, name, val)
        existing = self.get(kind, name)
        if existing:
            edit_type = 'edit'
        else:
            edit_type = 'add'
        nval = copy.deepcopy(val)
        for k, v in val.items():
            if isinstance(v, str) and v == '~':
                nval.pop(k)
        if kind != 'systems':
            try:
                self.server.xapi_object_edit(COBBLER_KIND_MAP[kind], name, edit_type, nval, self.token)
            except xmlrpc.client.Fault as e:
                raise Exception(e.faultString)
        else:
            # As dumb as it is, we _still_ need to handle systems differently.
            if 'interfaces' in nval:
                interfaces = nval.pop('interfaces')
            else:
                interfaces = {}
            try:
                self.server.xapi_object_edit(COBBLER_KIND_MAP[kind], name, edit_type, nval, self.token)
            except xmlrpc.client.Fault as e:
                raise Exception(e.faultString)
            handle = self.server.get_system_handle(name, self.token)
            ninterfaces = {}
            for iname, ival in interfaces.items():
                for k, v in ival.items():
                    if k in ['dns_name', 'ip_address', 'mac_address']:
                        if v:
                            ninterfaces[k.replace('_', '') + '-' + iname] = v
                    else:
                        ninterfaces[k + '-' + iname] = v
            self.server.modify_system(
                handle,
                'modify_interface',
                ninterfaces,
                self.token
            )
            self.server.save_system(handle, self.token)


    def set_file(self, kind, path, content):
        '''
        Sets the contents of the specified file to the specified value.
        '''
        if self.api_version < 3.0:
            return self.legacy_set_file(kind, path, content)
        if kind == 'snippets':
            self.server.write_autoinstall_snippet(path, content, self.token)
        elif kind == 'templates':
            self.server.write_autoinstall_template(path, content, self.token)

    def legacy_set_file(self, kind, path, content):
        '''
        Sets the contents of the specified file to the specified value (legacy).
        '''
        if kind == 'snippets':
            server_snippets_dir = self.server_settings.get('snippetsdir', '/var/lib/cobbler/snippets')
            if path.startswith('/'):
                true_path = path
            else:
                true_path = os.path.join(server_snippets_dir, path)
            try:
                self.server.read_or_write_snippet(
                    true_path,
                    False,
                    content,
                    self.token
                )
            except xmlrpc.client.Fault as e:
                raise Exception(e.faultString)
        elif kind == 'templates':
            server_templates_dir = os.path.dirname(self.server_settings.get('default_kickstart', '/var/lib/cobbler/kickstarts/default.ks'))
            if path.startswith('/'):
                true_path = path
            else:
                true_path = os.path.join(server_templates_dir, path)
            try:
                self.server.read_or_write_kickstart_template(
                    true_path,
                    False,
                    content,
                    self.token
                )
            except xmlrpc.client.Fault as e:
                raise Exception(e.faultString)

    def legacy_set(self, kind, name, val):
        '''
        Updates the cobbler server with the values from `val`.

        This version uses functions sourced from `self.legacy_get_funcs()`.
        '''
        f = self.legacy_get_funcs(kind)
        existing = self.get(kind, name)
        if existing:
            handle = f['handle'](name, self.token)
        else:
            handle = f['new'](self.token)
            f['modify'](handle, 'name', name, self.token)
        # The code below for merging the old and existing values is now handled
        # in the `update()` function.
        #if existing:
        #    true_val = _dict_merge(existing, val)
        #else:
        #    true_val = val
        #for k, v in true_val.items():
        for k, v in val.items():
            # Unfortunately, we need to handle the interfaces of systems
            # different from everything else. The general form is:
            # {key}-{interface}
            if kind == 'systems' and k == 'interfaces':
                interfaces_dict = {}
                # iname: bond0
                for iname, idata in v.items():
                    # ik: gateway
                    # iv: 10.11.32.1
                    for ik, iv in idata.items():
                        # Furthermore, things like "mac_address" are expected to
                        # be passed-in as "macaddress".
                        if ik in ['dns_name', 'ip_address', 'mac_address']:
                            interfaces_dict[ik.replace('_', '') + '-' + iname] = iv
                        else:
                            interfaces_dict[ik + '-' + iname] = iv
                f['modify'](handle, 'modify_interface', interfaces_dict, self.token)
            elif existing:
                if not k in existing or existing[k] != v:
                    f['modify'](handle, k, v, self.token)
            else:
                f['modify'](handle, k, v, self.token)
        f['save'](handle, self.token)

    def sync(self):
        '''
        Syncronizes changes (performs a "cobbler sync").
        '''
        self.server.sync(self.token)

    def validate(self, kind, name, val):
        '''
        Validates the specified Cobbler object, raising an exception if it is
        invalid.
        '''
        if not kind in COBBLER_KINDS:
            raise Exception('object kind is not one of ' + str(COBBLER_KINDS))
        if not name:
            raise Exception('object does not specify a name')
        if not isinstance(val, dict):
            raise Exception('object type is not a dictionary')
        if not val:
            raise Exception('object does not define any key-value pairs')
        if kind == 'distros':
            if not 'arch' in val:
                raise Exception('distribution does not specify an operating system architecture')
            if self.valid_distro_archs and not val['arch'] in self.valid_distro_archs:
                raise Exception('specified distribution operating system architecture is not one of ' + str(self.valid_distro_archs))
            if self.api_version >= 3.0 and not 'boot_loader' in val:
                raise Exception('distribution does not specify a boot loader')
            if self.api_version >= 3.0 and not val['boot_loader'] in COBBLER_BOOTLOADERS:
                raise Exception('specified distribution boot loader is not one of ' + str(COBBLER_BOOTLOADERS))
            if not 'breed' in val:
                raise Exception('distribution does not specify an operating system breed')
            if self.valid_distro_breeds and not val['breed'] in self.valid_distro_breeds:
                raise Exception(
                    'specified distribution operating system breed is not one of ' + str([k for k in self.valid_distro_breeds.keys()])
                )
            if not 'initrd' in val:
                raise Exception('distribution does not specify a pxeboot initrd file path')
            if not 'kernel' in val:
                raise Exception('distribution does not specify a pxeboot kernel file path')
            if not 'os_version' in val:
                raise Exception('distribution does not specify an operating system version')
            if self.valid_distro_breeds and not val['os_version'] in self.valid_distro_breeds[val['breed']]:
                raise Exception(
                    'specified distribution operating system version is not one of ' + str(self.valid_distro_breeds[val['breed']])
                )
        elif kind == 'mgmtclasses':
            if not 'class_name' in val:
                raise Exception('management class does not specify a class name')
        elif kind == 'profiles':
            if not 'distro' in val:
                raise Exception('profile does not specify a parent distribution')
        elif kind == 'repos':
            if not 'arch' in val:
                raise Exception('repository does not specify an operating system architecture')
            if not val['arch'] in COBBLER_REPO_ARCHS:
                raise Exception('specified repository architecture is not one of ' + str(COBBLER_REPO_ARCHS))
            if not 'breed' in val:
                raise Exception('repository does not specify a synchronization method (breed)')
            if not val['breed'] in COBBLER_REPO_BREEDS:
                raise Exception(
                    'specified respository synchronization method (breed) is not one of ' + str(COBBLER_REPO_BREEDS)
                )
        elif kind == 'systems':
            if not 'profile' in val and not 'image' in val:
                raise Exception('system does not specify a parent profile or image')
            if not 'interfaces' in val or not val['interfaces']:
                raise Exception('system does not specify any network interfaces')
            if 'interfaces' in val and val['interfaces']:
                if not isinstance(val['interfaces'], dict):
                    raise Exception('system interfaces not specified as a dictionary of interface specifications')
                for iname, ival in val['interfaces'].items():
                    if not isinstance(ival, dict):
                        raise Exception('system interface "' + iname + '" not specified as a dictionary of interface properties')
                    if 'mac_address' in ival and ival['mac_address'] and not VALID_MAC_REGEX.match(ival['mac_address']):
                        raise Exception('system interface "' + iname + '" does not specify a valid MAC address')
                    if 'interface_type' in ival and ival['interface_type'] and not ival['interface_type'] in COBBLER_INTERFACE_TYPES:
                        raise Exception('interface type of system interface "' + iname + '" is not one of ' + str(COBBLER_INTERFACE_TYPES))
                    if 'ip_address' in ival and ival['ip_address'] and not VALID_IPv4_REGEX.match(ival['ip_address']):
                        raise Exception('system interface "' + iname + '" does not specify a valid IPv4 address')

                

# --------------------------------------



# ----- Private (Helper) Functions -----

def _c(instring, color=C_BLUE):
    '''
    Colorizes the specified string.
    '''
    if args.color_output and not color is None:
        return color + instring + C_END
    else:
        return instring


def _dict_merge(dict1, dict2):
    '''
    Recursively merges two dictionaries. Unlike `_merge_yaml_data` however,
    lists are not extended.
    '''
    d2 = copy.deepcopy(dict2)
    if isinstance(dict1, dict) and isinstance(dict2, dict):
        d1 = copy.deepcopy(dict1)
        return_dict = {}
        for k, v in d2.items():
            if k in d1:
                if isinstance(d1[k], dict) and isinstance(v, dict):
                    return_dict[k] = _dict_merge(d1[k], v)
                else:
                    return_dict[k] = v
            else:
                return_dict[k] = v
        for k, v in d1.items():
            if not k in d2:
                return_dict[k] = v
        return return_dict
    return d2


def _flatten_dict(d, sep='.'):
    '''
    Flattens the specified dicitonary such that it becomes a one-dimensional set
    of key-value pairs where each depth is handled by `.` syntax.
    '''
    if not isinstance(d, dict):
        return d
    new = {}
    for k, v in copy.deepcopy(d).items():
        if isinstance(v, dict):
            for k2, v2 in _flatten_dict(v).items():
                new[str(k) + sep + str(k2)] = v2
        else:
            new[str(k)] = v
    return new


def _get_path(path, base_path=''):
    '''
    Returns the full path to a file specified in the configuration file.
    '''
    if path.startswith('/'):
        return path
    elif path.startswith('~'):
        return os.path.expanduser(path)
    else:
        if base_path:
            if '../' in base_path:
                return os.path.abspath(os.path.join(base_path, path))
            else:
                return os.path.normpath(os.path.join(base_path, path))
        else:
            return os.path.normpath(os.path.join(conf_dir, path))


def _merge_yaml_data(data1, data2):
    '''
    Returns the recursively-merged version of both YAML data objects.
    The second object has priority on conflicts.
    '''
    if isinstance(data1, str) and isinstance(data2, str):
        return data2
    if isinstance(data1, list) and isinstance(data2, list):
        return_list = data1.copy()
        return_list.extend(data2.copy())
        return return_list
    if isinstance(data1, dict) and isinstance(data2, dict):
        return_dict = data1.copy()
        for key, val in data2.items():
            if key in return_dict:
                return_dict[key] = _merge_yaml_data(return_dict[key], val)
            else:
                return_dict[key] = val
        return return_dict
    return data2


def _parse_arguments():
    '''
    Parses the command-line arguments into a global namespace called "args".
    '''
    # Do some pre-parsing for some of the environment variables to prevent crashes
    if not os.getenv('PROV_LOG_LEVEL', 'info') in ['info', 'debug']:
        sys.exit('Invalid value set for environment variable "PROV_LOG_LEVEL".')
    if not os.getenv('PROV_LOG_MODE', 'append') in ['append', 'overwrite']:
        sys.exit('Invalid value set for environment variable "PROV_LOG_MODE".')
    if not os.getenv('PROV_PORT', '80').isdigit():
        sys.exit('Invalid value set for environment variable "PROV_PORT".')
    argparser = argparse.ArgumentParser(
        description = HELP_DESCRIPTION,
        epilog = HELP_EPILOG,
        usage = '(prov -h|--help) | (prov <CONF> [-s SERVER] [...]) | (prov -D|--dump <CONF>)',
        add_help = False,
        formatter_class = lambda prog: argparse.RawDescriptionHelpFormatter(prog, max_help_position=45, width=100)
    )
    argparser.add_argument(
        'conf',
        help = 'Specifies the path to the declarative configuration YAML file to read Cobbler item specifications from. If "--dump" is passed to the script, this file will be overwritten with the configuration present on the target server.',
    )
    argparser.add_argument(
        '-a',
        '--api-path',
        default = os.getenv('PROV_API_PATH', 'cobbler_api'),
        dest = 'api_path',
        help = '[env: PROV_API_PATH] Specifies the API path endpoint to make requests to. Defaults to "cobbler_api".',
        metavar = 'STR'
    )
    argparser.add_argument(
        '-b',
        '--base-dir',
        default = os.getenv('PROV_BASE_DIR', ''),
        dest = 'base_dir',
        help = '[env: PROV_BASE_DIR] Specifies the base directory from which files will be searched for. Defaults to the directory containing the specified configuration file.',
        metavar = 'DIR'
    )
    argparser.add_argument(
        '--delete',
        action = 'store_true',
        dest = 'delete',
        help = 'Specifies that the script should delete any specifications on the server which are not present in the target configuration.'
    )
    argparser.add_argument(
        '-d',
        '--dry-run',
        action = 'store_true',
        dest = 'dry_run',
        help = 'Specifies that the script should only execute a dry-run, preventing changes from occuring to the specified Cobbler server.'
    )
    argparser.add_argument(
        '-D',
        '--dump',
        action = 'store_true',
        dest = 'dump',
        help = 'Specifies that the script should save the active configuration of the specified Cobbler server to the specified configuration file (instead of the script\'s usual operation).'
    )
    argparser.add_argument(
        '-h',
        '--help',
        action = 'help',
        help = 'Displays help and usage information.'
    )
    argparser.add_argument(
        '-f',
        '--log-file',
        default = os.getenv('PROV_LOG_FILE', ''),
        dest = 'log_file',
        help = '[env: PROV_LOG_FILE] Specifies a log file to write to in addition to stdout/stderr.',
        metavar = 'FILE'
    )
    argparser.add_argument(
        '-l',
        '--log-level',
        choices = ['info', 'debug'],
        default = os.getenv('PROV_LOG_LEVEL', 'info'),
        dest = 'log_level',
        help = '[env: PROV_LOG_LEVEL] Specifies the log level of the script, being either "info" or "debug". Defaults to "info". This option is ignored if "--log-file" is not specified.',
        metavar = 'LVL'
    )
    argparser.add_argument(
        '-m',
        '--log-mode',
        choices = ['append', 'overwrite'],
        default = os.getenv('PROV_LOG_MODE', 'append'),
        dest = 'log_mode',
        help = '[env: PROV_LOG_MODE] Specifies whether to "append" or "overwrite" the specified log file. Defaults to "append". This option is ignored if "--log-file" is not specified.',
        metavar = 'MODE'
    )
    argparser.add_argument(
        '--no-color',
        action = 'store_false',
        dest = 'color_output',
        help = 'Disables color output to stdout/stderr.'
    )
    argparser.add_argument(
        '-p',
        '--password',
        default = os.getenv('PROV_PASSWORD', 'cobbler'),
        dest = 'password',
        help = '[env: PROV_PASSWORD] Specifies the password to use when connecting to the specified cobbler server. Defaults to "cobbler".',
        metavar = 'STR'
    )
    argparser.add_argument(
        '-P',
        '--port',
        default = int(os.getenv('PROV_PORT', '80')),
        dest = 'port',
        help = '[env: PROV_PORT] Specifies the port on specified cobbler server to connect to. Defaults to "80".',
        metavar = 'INT',
        type = int
    )
    argparser.add_argument(
        '-s',
        '--server',
        default = os.getenv('PROV_SERVER', '127.0.0.1'),
        dest = 'server',
        help = '[env: PROV_SERVER] Specifies the FQDN or IP address of the cobbler server to connect to. Defaults to "127.0.0.1".',
        metavar = 'STR'
    )
    argparser.add_argument(
        '-S',
        '--snippets-dir',
        default = os.getenv('PROV_SNIPPETS_DIR', 'snippets'),
        dest = 'snippets_dir',
        help = '[env: PROV_SNIPPETS_DIR] Specifies the directory relative to the specified base directory within which autoinstallation snippets should be found. Defaults to "snippets".',
        metavar = 'DIR'
    )
    argparser.add_argument(
        '--ssl',
        action = 'store_true',
        dest = 'ssl',
        help = 'Specifies that the script should connect to the Cobbler API via https.'
    )
    argparser.add_argument(
        '-t',
        '--templates-dir',
        default = os.getenv('PROV_TEMPLATES_DIR', 'templates'),
        dest = 'templates_dir',
        help = '[env: PROV_TEMPLATES_DIR] Specifies the directory relative to the specified base directory within which autoinstallation templates (kickstarts) should be found. Defaults "templates".',
        metavar = 'DIR'
    )
    argparser.add_argument(
        '-u',
        '--username',
        default = os.getenv('PROV_USERNAME', 'cobbler'),
        dest = 'username',
        help = '[env: PROV_USERNAME] Specifies the username to use when connecting to the specified cobbler server. Defaults to "cobbler".',
        metavar = 'STR'
    )
    global args
    args = argparser.parse_args()


def _parse_file_paths(path_spec):
    '''
    Returns the equivalent list of file paths given a path specification.
    With the expection of globbing, the resulting paths are only computed and
    are not checked to be valid. If a glob results in no files, an empty list is
    returned.

    Examples:
    /foo/bar1.txt      ->  [/foo/bar1.txt]
    /foo/bar*.txt      ->  [/foo/bar1.txt, /foo/bar2.txt, ...]
    /foo/bar[1,2].txt  ->  [/foo/bar1.txt, /foo/bar2.txt]
    /foo/bar[1-3].txt  ->  [/foo/bar1.txt, /foo/bar2.txt, /foo/bar3.txt]
    '''
    if not '*' in path_spec and not '[' in path_spec and not ']' in path_spec:
        return [path_spec]
    elif '*' in path_spec:
        try:
            if not '**' in path_spec:
                return glob.glob(path_spec)
            elif path_spec.startswith('/'):
                base_path = '/'
                altered_path_spec = path_spec.lstrip('/')
            else:
                base_path = '.'
                altered_path_spec = path_spec
            return [f.as_posix() for f in pathlib.Path(base_path).glob(altered_path_spec) if f.is_file()]
        except Exception as e:
            raise Exception('path specification globbing encountered an exception - ' + str(e))
    elif '[' in path_spec and ']' in path_spec:
        paths = []
        guts = path_spec.split('[', 1)[1]
        if not ']' in guts:
            raise Exception('path specification has its shoelaces crossed')
        guts = guts.split(']', 1)[0]
        if ',' in guts:
            list_match = LIST_REGEX.match(path_spec)
            if not list_match:
                raise Exception('path specification does not contain a valid list expression')
            expr = list_match.group('expr')
            parts = expr[1:-1].split(',')
            for p in parts:
                if p:
                    paths.append(path_spec.replace(expr, p))
        elif '-' in guts:
            range_match = RANGE_REGEX.match(path_spec)
            if not range_match:
                raise Exception('path specification does not contain a valid range expression')
            expr = range_match.group('expr')
            lb = int(range_match.group('lower'))
            ub = int(range_match.group('upper'))
            if not ub > lb:
                raise Exception('upperbound in path specification range expression is not greater than the lowerbound')
            for i in range(lb, ub + 1):
                paths.append(path_spec.replace(expr, str(i)))
        else:
            raise Exception('path specification does not specify a range or list expression')
        return paths
    else:
        raise Exception('path specification does not have balanced brackets')


def _setup_logging():
    '''
    Sets-up logging.
    '''
    if args.log_file:
        try:
            if args.log_mode == 'append':
                logging_fmode = 'a'
            else:
                logging_fmode = 'w'
            if args.log_level == 'info':
                logging_level = logging.INFO
            else:
                logging_level = logging.DEBUG
            logging.basicConfig(
                filename = args.log_file,
                filemode = logging_fmode,
                level    = logging_level,
                format   = '[%(levelname)s] [%(asctime)s] [%(process)d] [%(module)s.%(funcName)s] %(message)s',
                datefmt  = '%m/%d/%Y %I:%M:%S %p'
            )
            logging.addLevelName(logging.CRITICAL, 'CRI')
            logging.addLevelName(logging.ERROR, 'ERR')
            logging.addLevelName(logging.WARNING, 'WAR')
            logging.addLevelName(logging.INFO, 'INF')
            logging.addLevelName(logging.DEBUG, 'DEB')
        except Exception as e:
            sys.exit('Unable to initialize logging system - ' + str(e) + '.')
    else:
        logger = logging.getLogger()
        logger.disabled = True


def _step(instring, color=C_BLUE):
    '''
    Formats the specified string as a "step".
    '''
    return _c('::', color) + ' ' + _c(instring, C_BOLD)


def _substep(instring, color=C_BLUE):
    '''
    Formats the specified string as a "sub-step".
    '''
    return '  ' + _c('-->', color) + ' ' + instring


def _subsubstep(instring, color=None):
    '''
    Formats the specified string as a "sub-sub-step".
    '''
    return '      ' + _c(instring, color)

# --------------------------------------



# ---------- Public Functions ----------

def connect():
    '''
    Establishes a connection to the Cobbler server, setting the global "cobbler"
    variable.
    '''
    EC = 5
    message(_step('Connecting to {server}...').format(server=args.server))
    logging.info('Connecting to {server}...'.format(server=args.server))
    global cobbler
    try:
        cobbler = Cobbler(
            api_endpoint = args.api_path,
            password = args.password,
            port = args.port,
            server = args.server,
            ssl = args.ssl,
            username = args.username
        )
    except Exception as e:
        emessage('  ' + _c(str(e) + '.', C_RED))
        logging.critical(str(e) + '.')
        sys.exit(EC)
    logging.debug('SERVER API VERSION: ' + str(cobbler.api_version))


def disconnect():
    '''
    Ends the connection to the Cobbler server (by logging out).
    '''
    EC = 13
    logging.debug('Disconnecting from {server}...'.format(server=args.server))
    try:
        cobbler.server.logout(cobbler.token)
    except Exception as e:
        message(_step('Disconnecting from {server}...').format(server=args.server))
        emessage('   ' + _c(str(e) + '.', C_RED))
        logging.critical(str(e) + '.')
        sys.exit(EC)


def dump_config():
    '''
    Handles the `--dump` argument.
    '''
    EC = 15
    message(_step('Dumping configuration...'))
    logging.info('Dumping configuration...')
    try:
        cobbler.dump(args.conf)
    except Exception as e:
        emessage('   ' + _c(str(e) + '.', C_RED))
        logging.critical(str(e) + '.')
        sys.exit(EC)


def emessage(instring):
    '''
    Prints the specified string to stderr.
    '''
    sys.stderr.write(instring + '\n')


def get_hostname():
    '''
    Obtains the hostname of the machine.
    '''
    logging.debug('Getting hostname and FQDN...')
    try:
        global hostname
        hostname = socket.gethostname().split('.', 1)[0]
        global fqdn
        fqdn = socket.getfqdn()
    except Exception as e:
        logging.critical('Error: Unable to discern hostname - ' + str(e) + '.')
        sys.exit(1)
    logging.debug('Hostname: ' + hostname)
    logging.debug('FQDN: ' + fqdn)


def main():
    '''
    The entrypoint of the script.
    '''
    # (2) Parse command-line arguments
    _parse_arguments()

    # (1) Setup logging
    _setup_logging()

    # Log CLI arguments at the DEBUG level
    logging.debug('----- CLI Arguments -----')
    dargs = vars(args)
    for a in dargs:
        logging.debug(a + ' : ' + str(dargs[a]))
    logging.debug('-------------------------')

    # (1) Get the hostname of the machine
    get_hostname()

    logging.info('Starting process...')

    # (2) Set-up and validate the environment
    validate_environment()

    if not args.dump:
        # (3) Parse configuration file
        parse_config()

        # (4) Validate configuration
        validate_config()

    # (5) Establish connection
    connect()

    if not args.dump:
        # (16) Update disk images
        if 'disk_images' in conf: update_disk_images()

        # (17) Update autoinstall snippets
        if 'snippets' in conf: update_files('snippets', 17)

        # (18) Update autoinstall templates (kickstarts)
        if 'templates' in conf: update_files('templates', 18)

        # (6) Update repos
        if 'repos' in conf: update('repos', 6)

        # (7) Update images
        if 'images' in conf: update('images', 7)

        # (8) Update distros
        if 'distros' in conf: update('distros', 8)

        # (9) Update management classes
        if 'mgmtclasses' in conf: update('mgmtclasses', 9)

        # (10) Update profiles
        if 'profiles' in conf: update('profiles', 10)

        # (11) Update systems
        if 'systems' in conf: update('systems', 11)

        # (12) Syncronize changes
        if not args.dry_run: sync()
    else:
        # (15) Dump configuration
        dump_config()

    # (13) Disconnect
    disconnect()

    logging.info('Process complete.')

    # We are done.
    sys.exit(0)


def message(instring):
    '''
    Prints the specified string to stdout.
    '''
    print(instring)


def parse_config():
    '''
    Parses the configuration YAML file into a global dictionary object.
    '''
    EC = 3
    message(_step('Loading configuration file(s)...'))
    logging.info('Loading configuration file(s)...')
    logging.debug('Reading configuration file...')
    try:
        with open(args.conf, 'r') as yamlf:
            conf_raw = yamlf.read()
    except Exception as e:
        message(_substep('Reading configuration file...'))
        emessage(_subsubstep('Error: Unable to read configuration file - ' + str(e) + '.', C_RED))
        logging.critical('Unable to read configuration file - ' + str(e) + '.')
        sys.exit(EC)
    logging.debug('Parsing configuration file...')
    try:
        global conf
        conf = yaml.safe_load(conf_raw)
    except Exception as e:
        message(_substep('Parsing configuration file...'))
        emessage(_subsubstep('Error: Unable to parse configuration file - ' + str(e) + '.', C_RED))
        logging.critical('Unable to parse configuration file - ' + str(e) + '.')
        sys.exit(EC)
    if 'include' in conf:
        logging.debug('Parsing configuration file includes...')
        if not isinstance(conf['include'], list):
            message(_substep('Parsing configuration file includes...'))
            emessage(_subsubstep('Error: Unable to parse configuration file includes - "include" specification is not a list of file paths.', C_RED))
            logging.critical('Unable to parse configuration file includes - "include" specification is not a list of file paths.')
            sys.exit(EC)
        flatten = lambda L: [item for sublist in L for item in sublist]
        try:
            flat_includes = flatten([_parse_file_paths(_get_path(p, os.path.dirname(args.conf))) for p in conf['include']])
        except Exception as flat_e:
            message(_substep('Parsing configuration file includes...'))
            emessage(_subsubstep('Error: Unable to parse configuration file includes - "include" specification parsing error - ' + str(flat_e) + '.', C_RED))
            logging.critical('Unable to parse configuration file includes - "include" specification parsing error - ' + str(flat_e) + '.')
            sys.exit(EC)
        for i in flat_includes:
            if not isinstance(i, str):
                message(_substep('Parsing configuration file includes...'))
                emessage(_subsubstep('Error: Unable to parse configuration file includes - "include" specification is not a list of file paths.', C_RED))
                logging.critical('Unable to parse configuration file includes - "include" specification is not a list of file paths.')
                sys.exit(EC)
            logging.debug('Validating configuration file include "' + i + '"...')
            if not os.path.isfile(i):
                message(_substep('Parsing configuration file includes...'))
                emessage(_subsubstep('Error: Unable to validate configuration file include "' + i + '" - value is not a path to an existing file.', C_RED))
                logging.critical('Unable to validate configuration file include "' + i + '" - value is not a path to an existing file.')
                sys.exit(EC)
            logging.debug('Loading configuration file include "' + i + '"...')
            try:
                with open(i, 'r') as ifile:
                    icontents = ifile.read()
            except Exception as e:
                message(_substep('Parsing configuration file includes...'))
                emessage(_subsubstep('Error: Unable to load configuration file include "' + i + '" - ' + str(e) + '.', C_RED))
                logging.critical('Unable to load configuration file include "' + i + '" - ' + str(e) + '.')
                sys.exit(EC)
            logging.debug('Parsing configuration file include "' + i + '"...')
            try:
                iconf = yaml.safe_load(icontents)
            except Exception as e:
                message(_substep('Parsing configuration file includes...'))
                emessage(_subsubstep('Error: Unable to parse configuration file include "' + i + '" - ' + str(e) + '.', C_RED))
                logging.critical('Unable to parse configuration file include "' + i + '" - ' + str(e) + '.')
                sys.exit(EC)
            logging.debug('Merging configuration file include "' + i + '"...')
            try:
                conf = _merge_yaml_data(conf, iconf)
            except Exception as e:
                message(_substep('Parsing configuration file includes...'))
                emessage(_subsubstep('Error: Unable to merge configuration file include "' + i + '" - ' + str(e) + '.', C_RED))
                logging.critical('Unable to merge configuration file include "' + i + '" - ' + str(e) + '.')
                sys.exit(EC)
    if 'snippets' in conf:
        logging.debug('Parsing snippets specification...')
        try:
            flat_snippets = flatten([_parse_file_paths(_get_path(p, snippets_dir)) for p in conf['snippets']])
        except Exception as e:
            message(_substep('Parsing snippets specification...'))
            emessage(_subsubstep('Error: Unable to parse snippets specification - ' + str(e) + '.'), C_RED)
            logging.critical('Unable to parse snippets specification - ' + str(e) + '.')
            sys.exit(EC)
        logging.debug('FLAT SNIPPETS: ' + str(flat_snippets))
        parsed_snippets = {}
        logging.debug('Reading snippets...')
        for path in flat_snippets:
            if os.path.isdir(path):
                logging.debug('Skipping "' + path + '" since it is a directory...')
                continue
            logging.debug('Reading "' + path + '"...')
            if not os.path.isfile(path):
                message(_substep('Reading snippets...'))
                emessage(_subsubstep('Error: Unable to read snippet "' + path + '" - file does not exist.', C_RED))
                logging.critical('Unable to read snippet "' + path + '" - file does not exist.')
                sys.exit(EC)
            try:
                with open(path, 'r') as f:
                    file_contents = f.read()
            except Exception as e:
                message(_substep('Reading snippets...'))
                emessage(_subsubstep('Error: Unable to read snippet "' + path + '" - ' + str(e) + '.', C_RED))
                logging.critical('Unable to read snippet "' + path + '" - ' + str(e) + '.')
                sys.exit(EC)
            parsed_snippets[os.path.relpath(path, snippets_dir)] = file_contents
        conf['snippets'] = parsed_snippets
    if 'templates' in conf:
        logging.debug('Parsing templates specification...')
        try:
            flat_templates = flatten([_parse_file_paths(_get_path(p, templates_dir)) for p in conf['templates']])
        except Exception as e:
            message(_substep('Parsing templates specification...'))
            emessage(_subsubstep('Error: Unable to parse templates specification - ' + str(e) + '.'), C_RED)
            logging.critical('Unable to parse templates specification - ' + str(e) + '.')
            sys.exit(EC)
        logging.debug('FLAT TEMPLATES: ' + str(flat_templates))
        parsed_templates = {}
        logging.debug('Reading templates...')
        for path in flat_templates:
            logging.debug('Reading "' + path + '"...')
            if not os.path.isfile(path):
                message(_substep('Reading templates...'))
                emessage(_subsubstep('Error: Unable to read template "' + path + '" - file does not exist.', C_RED))
                logging.critical('Unable to read template "' + path + '" - file does not exist.')
                sys.exit(EC)
            try:
                with open(path, 'r') as f:
                    file_contents = f.read()
            except Exception as e:
                message(_substep('Reading templates...'))
                emessage(_subsubstep('Error: Unable to read template "' + path + '" - ' + str(e) + '.', C_RED))
                logging.critical('Unable to read template "' + path + '" - ' + str(e) + '.')
                sys.exit(EC)
            parsed_templates[os.path.relpath(path, templates_dir)] = file_contents
        conf['templates'] = parsed_templates
    logging.debug('----- Configuration -----')
    for x in conf:
        logging.debug(x + ' : ' + str(conf[x]))
    logging.debug('-------------------------')


def sync():
    '''
    Performs a cobbler sync.
    '''
    EC = 12
    message(_step('Synchronizing changes...'))
    logging.info('Synchronizing changes...')
    try:
        if not args.dry_run: cobbler.sync()
    except Exception as e:
        emessage('   ' + _c('Error: Unable to synchronize changes - ' + str(e) + '.', C_RED))
        logging.critical('Unable to synchronize changes - ' + str(e) + '.')
        sys.exit(EC)


def update(kind, exit_code):
    '''
    Updates the specified type of cobbler object.
    '''
    EC = exit_code
    message(_step('Updating {kind}{dry_run}...').format(
        kind = kind,
        dry_run = ' (DRY RUN)' if args.dry_run else ''
    ))
    logging.info('Updating {kind}{dry_run}...'.format(
        kind = kind,
        dry_run = ' (DRY RUN)' if args.dry_run else ''
    ))
    for name, data in conf[kind].items():
        message(_substep(name))
        logging.debug('name: ' + name)
        if 'defaults' in conf and kind in conf['defaults']:
            try:
                full_data = _merge_yaml_data(conf['defaults'][kind], data)
            except Exception as e:
                emessage(_subsubstep('Error: Unable to merge default values - ' + str(e) + '.', C_RED))
                logging.critical('Unable to merge default values - ' + str(e) + '.')
                sys.exit(EC)
        else:
            full_data = data
        logging.debug('FULL DATA: ' + str(full_data))
        try:
            existing = cobbler.get(kind, name)
        except Exception as e:
            emessage(_subsubstep('Error: Unable to fetch existing entry - ' + str(e) + '.', C_RED))
            logging.critical('Unable to fetch existing entry - ' + str(e) + '.')
            sys.exit(EC)
        logging.debug('EXISTING CONFIG: ' + str(existing))
        if not existing:
            message(_subsubstep('NEW ENTRY', color=C_GREEN))
            logging.debug('DIFF: NEW ENTRY')
        else:
            try:
                diff = cobbler.diff(kind, name, full_data)
            except Exception as e:
                emessage(_subsubstep('Error: Unable to obtain diff - ' + str(e) + '.', C_RED))
                logging.critical('Unable to obtain diff - ' + str(e) + '.')
                sys.exit(EC)
            if not diff:
                logging.debug('DIFF: NO CHANGE')
            else:
                for k, v in diff.items():
                    if v[0] is None or (isinstance(v[0], str) and not v[0]):
                        message(_subsubstep('{k}: {new}'.format(
                            k = k,
                            new = _c(str(v[1]), C_BLUE)
                        ), None))
                        logging.debug('DIFF: {k}: {new}'.format(
                            k = k,
                            new = str(v[1])
                        ))
                    else:
                        msg = k + ': ' + _c(str(v[0]), C_BLUE) + ' --> ' + _c(str(v[1]), C_GREEN)
                        message(_subsubstep(msg))
                        logging.debug('DIFF: {k}: {old} --> {new}'.format(
                            k = k,
                            old = str(v[0]),
                            new = str(v[1])
                        ))
        if existing:
            merged_data = cobbler.prepare(kind, name, _dict_merge(existing, full_data))
        else:
            merged_data = cobbler.prepare(kind, name, full_data)
        logging.debug('MERGED DATA: ' + str(merged_data))
        logging.debug('Validating item specification...')
        try:
            cobbler.validate(kind, name, merged_data)
        except Exception as e:
            emessage(_subsubstep('Error: Unable to validate entry - ' + str(e) + '.', C_RED))
            logging.critical('Unable to validate entry - ' + str(e) + '.')
            sys.exit(EC)
        logging.debug('Checking for comments...')
        if not 'comment' in merged_data or not merged_data['comment']:
            emessage(_subsubstep('Warning: Entry does not specify a comment (we should always document our stuff)!', C_ORANGE))
            logging.warning('Entry does not specify a comment (we should always document our stuff)!')
        logging.debug('Invoking set()...')
        if not args.dry_run:
            try:
                cobbler.set(kind, name, merged_data)
            except Exception as e:
                emessage(_subsubstep('Error: Unable to update entry - ' + str(e) + '.', C_RED))
                logging.critical('Unable to update entry - ' + str(e) + '.')
                sys.exit(EC)
    if args.delete:
        logging.debug('Looking for items to delete...')
        for item in cobbler.data[kind]:
            if not item['name'] in conf[kind]:
                message(_substep(item['name']))
                logging.debug('Deleting "{i}"...'.format(i=item['name']))
                try:
                    if not args.dry_run:
                        cobbler.delete(kind, item['name'])
                        message(_subsubstep('DELETED ITEM', C_ORANGE))
                    else:
                        message(_subsubstep('WOULD DELETE', C_ORANGE))
                except Exception as e:
                    emessage(_subsubstep('Error: Unable to delete entry - ' + str(e) + '.', C_RED))
                    logging.critical('Unable to delete entry - ' + str(e) + '.')
                    sys.exit(EC)


def update_disk_images():
    '''
    Updates the disk images on the target Cobbler server.
    '''
    EC = 16
    logging.info('Updating disk images...')
    message(_step('Updating disk images...'))


def update_files(kind, EC):
    '''
    Updates the autoinstallation templates (kickstarts) or snippets on the
    target Cobbler server.
    '''
    message(_step('Updating {kind}{dry_run}...').format(
        kind = kind,
        dry_run = ' (DRY RUN)' if args.dry_run else ''
    ))
    logging.info('Updating {kind}{dry_run}...'.format(
        kind = kind,
        dry_run = ' (DRY RUN)' if args.dry_run else ''
    ))
    for path, contents in conf[kind].items():
        message(_substep(path))
        logging.debug('path: ' + path)
        try:
            existing = cobbler.get_file(kind, path)
        except Exception as e:
            emessage(_subsubstep('Error: Unable to fetch existing entry - ' + str(e) + '.', C_RED))
            logging.critical('Unable to fetch existing entry - ' + str(e) + '.')
            sys.exit(EC)
        if not existing:
            message(_subsubstep('NEW ENTRY', color=C_GREEN))
            logging.debug('DIFF: NEW ENTRY')
        else:
            try:
                diff = cobbler.diff_file(kind, path, contents)
            except Exception as e:
                emessage(_subsubstep('Error: Unable to obtain diff - ' + str(e) + '.', C_RED))
                logging.critical('Unable to obtain diff - ' + str(e) + '.')
                sys.exit(EC)
            if not diff:
                logging.debug('DIFF: NO CHANGE')
            else:
                for line in diff:
                    logging.debug('DIFF: ' + line.strip())
                    if line.startswith('+'):
                        message(_subsubstep(line.strip(), C_GREEN))
                    elif line.startswith('-'):
                        message(_subsubstep(line.strip(), C_RED))
                    elif line.startswith('@@'):
                        message(_subsubstep(line.strip(), C_BLUE))
                    else:
                        message(_subsubstep(line.strip()))
        logging.debug('Invoking set_file()...')
        if not args.dry_run:
            try:
                cobbler.set_file(kind, path, contents)
            except Exception as e:
                emessage(_subsubstep('Error: Unable to update entry - ' + str(e) + '.', C_RED))
                logging.critical('Unable to update entry - ' + str(e) + '.')
                sys.exit(EC)
    if args.delete:
        logging.debug('Looking for items to delete...')
        for item in cobbler.files[kind]:
            if not item in conf[kind]:
                message(_substep(item))
                logging.debug('Deleting "{i}"...'.format(i=item))
                try:
                    if not args.dry_run:
                        cobbler.delete_file(kind, item)
                        message(_subsubstep('DELETED ITEM', C_ORANGE))
                    else:
                        message(_subsubstep('WOULD DELETE', C_ORANGE))
                except Exception as e:
                    emessage(_subsubstep('Warning: Unable to delete entry - ' + str(e) + '.', C_ORANGE))
                    logging.warning('Unable to delete entry - ' + str(e) + '.')


def validate_config():
    '''
    Validates the fully-parsed configuration.
    '''
    EC = 4
    logging.debug('Validating configuration...')
    for kind in COBBLER_KINDS:
        if kind in conf:
            if not isinstance(conf[kind], dict):
               message(_substep('Validating configuration...'))
               emessage(_subsubstep('Error: "{kind}" specification is not a dictionary object.'.format(kind=kind), C_RED))
               logging.critical('"{kind}" specification is not a dictionary object.'.format(kind=kind))
               sys.exit(EC)
            if any(not isinstance(conf[kind][x], dict) for x in conf[kind]):
               message(_substep('Validating configuration...'))
               emessage(_subsubstep('Error: One or more items within "{kind}" specification are not dictionary objects.'.format(kind=kind), C_RED))
               logging.critical('One or more items within "{kind}" specification are not dictionary objects.'.format(kind=kind))
               sys.exit(EC)


def validate_environment():
    '''
    Validates that the executing environment is sufficient to proceed.
    '''
    EC = 2
    message(_step('Validating working environment...'))
    logging.info('Validating working environment...')
    if not args.dump:
        message(_substep('Validating configuration file...'))
        logging.debug('Validating configuration file...')
    if not os.path.isfile(args.conf) and not args.dump:
        if not os.path.isdir(args.conf):
            emessage(_subsubstep('Error: Specified configuration file path does not exist.', C_RED))
            logging.critical('Specified configuration file path does not exist.')
            sys.exit(EC)
        else:
            logging.debug('Selecting suitable configuration file within specified directory...')
            files = [x for x in os.listdir(args.conf) if os.path.isfile(os.path.join(args.conf, x))]
            if not files:
                emessage(_subsubstep('Error: Specified configuration file directory does not contain any configuration files.', C_RED))
                logging.critical('Specified configuration file directory does not contain any configuration files.')
                sys.exit(EC)
            elif 'prov.yaml' in files:
                args.conf = os.path.join(args.conf, 'prov.yaml')
            elif 'prov.yml' in files:
                args.conf = os.path.join(args.conf, 'prov.yml')
            elif hostname + '.yaml' in files:
                args.conf = os.path.join(args.conf, hostname + '.yaml')
            elif hostname + '.yml' in files:
                args.conf = os.path.join(args.conf, hostname + '.yml')
            else:
                found_match = False
                for f in files:
                    if (f.endswith('.yaml') or f.endswith('.yml')) and f.rsplit('.', 1)[0] in hostname:
                        args.conf = os.path.join(args.conf, f)
                        found_match = True
                        break
                if not found_match:
                    emessage(_subsubstep('Error: Specified configuration file directory does not contain any selectable configuration files.', C_RED))
                    logging.critical('Specified configuration file directory does not contain any selectable configuration files.')
                    sys.exit(EC)
            message(_subsubstep('Automatically selected configuration file "' + args.conf + '".', C_BLUE))
            logging.info('Automatically selected configuration file "' + args.conf + '".')
    global files_dir
    if not args.base_dir:
        files_dir = os.path.dirname(args.conf)
    else:
        files_dir = args.base_dir
    logging.debug('FILES DIR: ' + files_dir)
    global snippets_dir
    if args.snippets_dir.startswith('/'):
        snippets_dir = args.snippets_dir
    else:
        snippets_dir = os.path.join(files_dir, args.snippets_dir)
    logging.debug('SNIPPETS DIR: ' + snippets_dir)
    global templates_dir
    if args.templates_dir.startswith('/'):
        templates_dir = args.templates_dir
    else:
        templates_dir = os.path.join(files_dir, args.templates_dir)
    logging.debug('TEMPLATES DIR: ' + templates_dir)


# --------------------------------------



# ---------- Boilerplate Magic ---------

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError) as ki:
        sys.stderr.write('Recieved keyboard interrupt!\n')
        sys.exit(100)

# --------------------------------------
