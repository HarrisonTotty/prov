# Configuration

`prov` is supplied a _Declarative Configuration File_ at runtime, either
explicitly or implicitly (by providing the script with a directory). The
declarative configuration file is a YAML document which contains:

* Additional YAML file `include` statements.
* Cobbler item specifications (such as `distros` or `systems`).
* Default values for Cobbler items.
* Cobbler autoinstallation file specifications (kickstarts and snippets).


----
## Configuration File Includes

A declarative configuration file may merge its definitions with other YAML
files, whose paths are mapped as list elements in the `include` key like so:

```yaml
# Primary Configuration File
# --------------------------

# Include additional configuration files.
include:
  - 'include/defaults.yaml'
  - 'include/distros.yaml'
  - 'include/systems.yaml'
```

These paths, like most file paths in `prov`, are relative to the location of the
primary declarative configuration file and _not_ the working directory the
script was executed in.

As stated above, these files have their definitions _merged_ with the primary
configuration file, so if `foo: 'bar'` is defined in `primary.yaml` and
`foo: 'baz'` is defined in `included.yaml`, then `prov` will assume that `foo`
is mapped to `baz`.


----
## Cobbler Item Specifications

The bulk of a declarative configuration file comprises specifications for the
various types of data items utilized by Cobbler. These are things like Cobbler
profiles, systems, and management classes. In general, each of these item types
is defined by a keyword such as `systems`, which maps to a dictionary of the
items themselves by _name_. Each individual item is also a dictionary of
key-value pairs, where the potential keys and values vary on the type of item.
Below is an example of defining a pair of Cobbler systems which share the same
Cobbler profile:

```yaml
profiles:
  'example-profile':
    comment: 'An example profile that will be inherited'
    distro: 'centos'
    
systems:
  'system1':
    comment: 'Example system 1'
    hostname: 'system1'
    profile: 'example-profile'
  'system2':
    comment: 'Example system 2'
    hostname: 'system1'
    profile: 'example-profile'
```

The subsections below will further define the layout of each different item
type. For more general information regarding the purpose of each key, refer to
the source code of the various items
[here](https://github.com/cobbler/cobbler/tree/master/cobbler/items). For more
information specific to Cobbler's implementation of its XMLRPC API, see the
contents of
[remote.py](https://github.com/cobbler/cobbler/blob/master/cobbler/remote.py).

The following keys are set by Cobbler internally and _should not_ be specified:

* `ctime`
* `depth`
* `ipv6_autoconfiguration`
* `mtime`
* `parent`
* `repos_enabled`
* `uid`

----
## Cobbler Autoinstallation File Specifications

In addition to managing Cobbler systems, repositories, and other data-based
definitions, `prov` can also manage autoinstallation files such as templates
(kickstarts) and snippets. These are specified with the `snippets` and
`templates` keys, respectively. The value associated with these keys is a list
of file path expressions (explained further below) where relative paths are
presumed to correspond to the snippets and templates directories supplied to the
script via the `-S`/`--snippets-dir` and `-t`/`--templates-dir` CLI arguments.

----
## File Path Conventions & Expressions

As alluded to above, file paths for keys like `include` may be specified via a
relative path (like `"foo.yaml"`) which is relative to the primary declarative
configuration file, or via an absolute path (like `"/etc/foo.yaml"` or
`"~/foo.yaml"`). In addition to relative vs. absolute paths, each path may be
expanded to multiple paths via wildcard and list/range expressions:

* A _wildcard expression_ (or _glob expression_) matches files in the same way
  that a shell would match them. For example, `"foo*.yaml"` would match
  `["foo1.yaml", "foo-bar.yaml", ...]`. Double wildcards like
  `"/foo/**/bar.yaml"` may be used to recursively glob for files.

* A _range expression_ matches files according to a specified integer range
  defined in the form `[x-y]`, where `x` is the lower-bound of the range and `y`
  is the upper-bound (inclusive). For example, `"foo[1-3].yaml"` would match
  `["foo1.yaml", "foo2.yaml", "foo3.yaml"]`. 

* A _list expression_ matches files according to a specified subset list of
  character sequences in the form `[a,b,c,...]`. For example,
  `"foo-[bar,baz].yaml"` would match `["foo-bar.yaml", "foo-baz.yaml"]`. 
