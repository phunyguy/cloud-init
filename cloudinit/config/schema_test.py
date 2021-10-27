#!/usr/bin/env python3
import sys
import yaml
import argparse
from collections import defaultdict
from copy import deepcopy
from textwrap import dedent
import logging
import os
import re
import sys
import yaml
import pprint

_YAML_MAP = {True: 'true', False: 'false', None: 'null'}
SCHEMA_UNDEFINED = b'UNDEFINED'
CLOUD_CONFIG_HEADER = b'#cloud-config'
SCHEMA_DOC_TMPL = """
{name}
{title_underbar}
**Summary:** {title}

{description}

**Internal name:** ``{id}``

**Module frequency:** {frequency}

**Supported distros:** {distros}

**Config schema**:
{property_doc}
{examples}
"""
SCHEMA_PROPERTY_TMPL = '{prefix}**{prop_name}:** ({type}) {description}'
SCHEMA_LIST_ITEM_TMPL = (
    '{prefix}Each item in **{prop_name}** list supports the following keys:')
SCHEMA_EXAMPLES_HEADER = '\n**Examples**::\n\n'
SCHEMA_EXAMPLES_SPACER_TEMPLATE = '\n    # --- Example{0} ---'


class SchemaValidationError(ValueError):
    """Raised when validating a cloud-config file against a schema."""

    def __init__(self, schema_errors=()):
        """Init the exception an n-tuple of schema errors.

        @param schema_errors: An n-tuple of the format:
            ((flat.config.key, msg),)
        """
        self.schema_errors = schema_errors
        error_messages = [
            '{0}: {1}'.format(config_key, message)
            for config_key, message in schema_errors]
        message = "Cloud config schema errors: {0}".format(
            ', '.join(error_messages))
        super(SchemaValidationError, self).__init__(message)


def is_schema_byte_string(checker, instance):
    """TYPE_CHECKER override allowing bytes for string type

    For jsonschema v. 3.0.0+
    """
    try:
        from jsonschema import Draft4Validator
    except ImportError:
        return False
    return (Draft4Validator.TYPE_CHECKER.is_type(instance, "string") or
            isinstance(instance, (bytes,)))


def validate_cloudconfig_schema(config, schema, strict=False):
    """Validate provided config meets the schema definition.

    @param config: Dict of cloud configuration settings validated against
        schema.
    @param schema: jsonschema dict describing the supported schema definition
       for the cloud config module (config.cc_*).
    @param strict: Boolean, when True raise SchemaValidationErrors instead of
       logging warnings.

    @raises: SchemaValidationError when provided config does not validate
        against the provided schema.
    """
    try:
        import jsonschema
        from jsonschema import Draft6Validator as Draft4Validator, FormatChecker
        from jsonschema.validators import create, extend
    except ImportError:
        logging.debug(
            'Ignoring schema validation. python-jsonschema is not present')
        return

    # Allow for bytes to be presented as an acceptable valid value for string
    # type jsonschema attributes in cloud-init's schema.
    # This allows #cloud-config to provide valid yaml "content: !!binary | ..."
    if hasattr(Draft4Validator, 'TYPE_CHECKER'):  # jsonschema 3.0+
        type_checker = Draft4Validator.TYPE_CHECKER.redefine(
            'string', is_schema_byte_string)
        cloudinitValidator = extend(Draft4Validator, type_checker=type_checker)
    else:  # jsonschema 2.6 workaround
        types = Draft4Validator.DEFAULT_TYPES
        # Allow bytes as well as string (and disable a spurious
        # unsupported-assignment-operation pylint warning which appears because
        # this code path isn't written against the latest jsonschema).
        types['string'] = (str, bytes)  # pylint: disable=E1137
        cloudinitValidator = create(
            meta_schema=Draft4Validator.META_SCHEMA,
            validators=Draft4Validator.VALIDATORS,
            version="draft4",
            default_types=types)
    logging.warning('Schema validator type: %s', type(cloudinitValidator))
    jsonschema.Draft4Validator.check_schema(schema)
    jsonschema.Draft6Validator.check_schema(schema)
    jsonschema.Draft7Validator.check_schema(schema)
    cloudinitValidator.check_schema(schema)
    validator = cloudinitValidator(schema, format_checker=FormatChecker())
    errors = ()
    for error in sorted(validator.iter_errors(config), key=lambda e: e.path):
        logging.warning('Schema error: %s', error)

        path = '.'.join([str(p) for p in error.path])
        errors += ((path, error.message),)

    if errors:
        print(errors)
        if strict:
            raise SchemaValidationError(errors)
        else:
            messages = ['{0}: {1}'.format(k, msg) for k, msg in errors]
            logging.warning('Invalid config:\n%s', '\n'.join(messages))
# this will match 'XXX:YYY' (ie, 'cloud-archive:foo' or 'ppa:bar')
ADD_APT_REPO_MATCH = r"^[\w-]+:\w"

frequency ='once'
distros = ["ubuntu", "debian"]
mirror_property = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'arches': {
                'type': 'array',
                'items': {
                    'type': 'string'
                },
                'minItems': 1
            },
            'uri': {
                'type': 'string',
                'format': 'uri'
            },
            'search': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'format': 'uri'
                },
                'minItems': 1
            },
            'search_dns': {
                'type': 'boolean',
            },
            'keyid': {
                'type': 'string'
            },
            'key': {
                'type': 'string'
            },
            'keyserver': {
                'type': 'string'
            }
        },
        'required': ['arches'],
        'additionalProperties': False,
    }
}
schema = {
    'id': 'cc_apt_configure',
    'name': 'Apt Configure',
    'title': 'Configure apt for the user',
    'description': dedent("""\
        This module handles both configuration of apt options and adding
        source lists.  There are configuration options such as
        ``apt_get_wrapper`` and ``apt_get_command`` that control how
        cloud-init invokes apt-get. These configuration options are
        handled on a per-distro basis, so consult documentation for
        cloud-init's distro support for instructions on using
        these config options.

        .. note::
            To ensure that apt configuration is valid yaml, any strings
            containing special characters, especially ``:`` should be quoted.

        .. note::
            For more information about apt configuration, see the
            ``Additional apt configuration`` example."""),
    'distros': distros,
    'examples': [dedent("""\
        apt:
          preserve_sources_list: false
          disable_suites:
            - $RELEASE-updates
            - backports
            - $RELEASE
            - mysuite
          primary:
            - arches:
                - amd64
                - i386
                - default
              uri: 'http://us.archive.ubuntu.com/ubuntu'
              search:
                - 'http://cool.but-sometimes-unreachable.com/ubuntu'
                - 'http://us.archive.ubuntu.com/ubuntu'
              search_dns: <true/false>
            - arches:
                - s390x
                - arm64
              uri: 'http://archive-to-use-for-arm64.example.com/ubuntu'
          security:
            - arches:
                - default
              search_dns: true
          sources_list: |
              deb $MIRROR $RELEASE main restricted
              deb-src $MIRROR $RELEASE main restricted
              deb $PRIMARY $RELEASE universe restricted
              deb $SECURITY $RELEASE-security multiverse
          debconf_selections:
              set1: the-package the-package/some-flag boolean true
          conf: |
              APT {
                  Get {
                      Assume-Yes 'true';
                      Fix-Broken 'true';
                  }
              }
          proxy: 'http://[[user][:pass]@]host[:port]/'
          http_proxy: 'http://[[user][:pass]@]host[:port]/'
          ftp_proxy: 'ftp://[[user][:pass]@]host[:port]/'
          https_proxy: 'https://[[user][:pass]@]host[:port]/'
          sources:
              source1:
                  keyid: 'keyid'
                  keyserver: 'keyserverurl'
                  source: 'deb http://<url>/ xenial main'
              source2:
                  source: 'ppa:<ppa-name>'
              source3:
                  source: 'deb $MIRROR $RELEASE multiverse'
                  key: |
                      ------BEGIN PGP PUBLIC KEY BLOCK-------
                      <key data>
                      ------END PGP PUBLIC KEY BLOCK-------""")],
    'frequency': frequency,
    'type': 'object',
    'properties': {
        'apt': {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'preserve_sources_list': {
                    'type': 'boolean',
                    'default': False,
                    'description': dedent("""\
                        By default, cloud-init will generate a new sources
                        list in ``/etc/apt/sources.list.d`` based on any
                        changes specified in cloud config. To disable this
                        behavior and preserve the sources list from the
                        pristine image, set ``preserve_sources_list``
                        to ``true``.

                        The ``preserve_sources_list`` option overrides
                        all other config keys that would alter
                        ``sources.list`` or ``sources.list.d``,
                        **except** for additional sources to be added
                        to ``sources.list.d``.""")
                },
                'disable_suites': {
                    'type': 'array',
                    'item': {
                        'type': 'string'
                    },
                    'uniqueItems': True,
                    'description': dedent("""\
                        Entries in the sources list can be disabled using
                        ``disable_suites``, which takes a list of suites
                        to be disabled. If the string ``$RELEASE`` is
                        present in a suite in the ``disable_suites`` list,
                        it will be replaced with the release name. If a
                        suite specified in ``disable_suites`` is not
                        present in ``sources.list`` it will be ignored.
                        For convenience, several aliases are provided for
                        ``disable_suites``:

                            - ``updates`` => ``$RELEASE-updates``
                            - ``backports`` => ``$RELEASE-backports``
                            - ``security`` => ``$RELEASE-security``
                            - ``proposed`` => ``$RELEASE-proposed``
                            - ``release`` => ``$RELEASE``.

                        When a suite is disabled using ``disable_suites``,
                        its entry in ``sources.list`` is not deleted; it
                        is just commented out.""")
                },
                'primary': {
                    **mirror_property,
                    'description': dedent("""\
                        The primary and security archive mirrors can
                        be specified using the ``primary`` and
                        ``security`` keys, respectively. Both the
                        ``primary`` and ``security`` keys take a list
                        of configs, allowing mirrors to be specified
                        on a per-architecture basis. Each config is a
                        dictionary which must have an entry for
                        ``arches``, specifying which architectures
                        that config entry is for. The keyword
                        ``default`` applies to any architecture not
                        explicitly listed. The mirror url can be specified
                        with the ``uri`` key, or a list of mirrors to
                        check can be provided in order, with the first
                        mirror that can be resolved being selected. This
                        allows the same configuration to be used in
                        different environment, with different hosts used
                        for a local apt mirror. If no mirror is provided
                        by ``uri`` or ``search``, ``search_dns`` may be
                        used to search for dns names in the format
                        ``<distro>-mirror`` in each of the following:

                            - fqdn of this host per cloud metadata,
                            - localdomain,
                            - domains listed in ``/etc/resolv.conf``.

                        If there is a dns entry for ``<distro>-mirror``,
                        then it is assumed that there is a distro mirror
                        at ``http://<distro>-mirror.<domain>/<distro>``.
                        If the ``primary`` key is defined, but not the
                        ``security`` key, then then configuration for
                        ``primary`` is also used for ``security``.
                        If ``search_dns`` is used for the ``security``
                        key, the search pattern will be
                        ``<distro>-security-mirror``.

                        Each mirror may also specify a key to import via
                        any of the following optional keys:

                            - ``keyid``: a key to import via shortid or \
                                  fingerprint.
                            - ``key``: a raw PGP key.
                            - ``keyserver``: alternate keyserver to pull \
                                    ``keyid`` key from.

                        If no mirrors are specified, or all lookups fail,
                        then default mirrors defined in the datasource
                        are used. If none are present in the datasource
                        either the following defaults are used:

                            - ``primary`` => \
                            ``http://archive.ubuntu.com/ubuntu``.
                            - ``security`` => \
                            ``http://security.ubuntu.com/ubuntu``
                        """)},
                'security': {
                    **mirror_property,
                    'description': dedent("""\
                        Please refer to the primary config documentation""")
                },
                'add_apt_repo_match': {
                    'type': 'string',
                    'default': ADD_APT_REPO_MATCH,
                    'description': dedent("""\
                        All source entries in ``apt-sources`` that match
                        regex in ``add_apt_repo_match`` will be added to
                        the system using ``add-apt-repository``. If
                        ``add_apt_repo_match`` is not specified, it
                        defaults to ``{}``""".format(ADD_APT_REPO_MATCH))
                },
                'debconf_selections': {
                    'type': 'object',
                    'items': {'type': 'string'},
                    'description': dedent("""\
                        Debconf additional configurations can be specified as a
                        dictionary under the ``debconf_selections`` config
                        key, with each key in the dict representing a
                        different set of configurations. The value of each key
                        must be a string containing all the debconf
                        configurations that must be applied. We will bundle
                        all of the values and pass them to
                        ``debconf-set-selections``. Therefore, each value line
                        must be a valid entry for ``debconf-set-selections``,
                        meaning that they must possess for distinct fields:

                        ``pkgname question type answer``

                        Where:

                            - ``pkgname`` is the name of the package.
                            - ``question`` the name of the questions.
                            - ``type`` is the type of question.
                            - ``answer`` is the value used to ansert the \
                            question.

                        For example: \
                        ``ippackage ippackage/ip string 127.0.01``
                    """)
                },
                'sources_list': {
                    'type': 'string',
                    'description': dedent("""\
                       Specifies a custom template for rendering
                       ``sources.list`` . If no ``sources_list`` template
                       is given, cloud-init will use sane default. Within
                       this template, the following strings will be
                       replaced with the appropriate values:

                            - ``$MIRROR``
                            - ``$RELEASE``
                            - ``$PRIMARY``
                            - ``$SECURITY``""")
                },
                'conf': {
                    'type': 'string',
                    'description': dedent("""\
                        Specify configuration for apt, such as proxy
                        configuration. This configuration is specified as a
                        string. For multiline apt configuration, make sure
                        to follow yaml syntax.""")
                },
                'https_proxy': {
                    'type': 'string',
                    'description': dedent("""\
                        More convenient way to specify https apt proxy.
                        https proxy url is specified in the format
                        ``https://[[user][:pass]@]host[:port]/``.""")
                },
                'http_proxy': {
                    'type': 'string',
                    'description': dedent("""\
                        More convenient way to specify http apt proxy.
                        http proxy url is specified in the format
                        ``http://[[user][:pass]@]host[:port]/``.""")
                },
                'proxy': {
                    'type': 'string',
                    'description': 'Alias for defining a http apt proxy.'
                },
                'ftp_proxy': {
                    'type': 'string',
                    'description': dedent("""\
                        More convenient way to specify ftp apt proxy.
                        ftp proxy url is specified in the format
                        ``ftp://[[user][:pass]@]host[:port]/``.""")
                },
                'sources': {
                    'type': 'object',
                    'items': {'type': 'string'},
                    'description': dedent("""\
                        Source list entries can be specified as a
                        dictionary under the ``sources`` config key, with
                        each key in the dict representing a different source
                        file. The key of each source entry will be used
                        as an id that can be referenced in other config
                        entries, as well as the filename for the source's
                        configuration under ``/etc/apt/sources.list.d``.
                        If the name does not end with ``.list``, it will
                        be appended. If there is no configuration for a
                        key in ``sources``, no file will be written, but
                        the key may still be referred to as an id in other
                        ``sources`` entries.

                        Each entry under ``sources`` is a dictionary which
                        may contain any of the following optional keys:

                            - ``source``: a sources.list entry \
                                  (some variable replacements apply).
                            - ``keyid``: a key to import via shortid or \
                                  fingerprint.
                            - ``key``: a raw PGP key.
                            - ``keyserver``: alternate keyserver to pull \
                                    ``keyid`` key from.

                        The ``source`` key supports variable
                        replacements for the following strings:

                            - ``$MIRROR``
                            - ``$PRIMARY``
                            - ``$SECURITY``
                            - ``$RELEASE``""")
                }
            }
        }
    }
}



if __name__ == "__main__":
    bads = 0
    for fn in sys.argv[1:]:
        sys.stdout.write("%s" % (fn))
        try:
            fh = open(fn, 'rb')
            config = yaml.safe_load(fh.read().decode('utf-8'))
            fh.close()
            sys.stdout.write(" - ok\n")
        except Exception as e:
            sys.stdout.write(" - bad (%s)\n" % (e))
            bads += 1
    if bads > 0:
        sys.exit(1)

    import jsonschema
    import pprint
    mymeta = jsonschema.Draft4Validator.META_SCHEMA
    mymeta['additionalProperties'] = False
    #mymeta['properties']['additionalProperties']['type'] = 'boolean'
    mymeta['properties']['name'] = {'type': 'string'}
    mymeta['properties']['examples'] = {'type': 'array'}
    mymeta['properties']['distros'] = {'type': 'array'}
    mymeta['properties']['frequency'] = {'type': 'string'}
    validate_cloudconfig_schema(config, schema)
    #pprint.pprint(mymeta)
