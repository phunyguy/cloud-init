import pathlib
import importlib
import sys
import inspect
import logging
from cloudinit.config.schema import is_schema_byte_string


def test_modules():
    '''Validate all modules with a stricter metaschema'''
    for (name, value) in get_schemas().items():
        if value:
            validate_cloudconfig_schema(value)
        else:
            logging.warning("module {} has no schema definition".format(name))


def get_schemas():
    '''Return all module schemas

    Assumes that module schemas have the variable name "schema"
    '''
    schemas = {}

    files = list(pathlib.Path('../../cloudinit/config/').glob('cc_*.py'))
    modules = [mod.stem for mod in files]

    for module in modules:
        importlib.import_module('cloudinit.config.{}'.format(module))

    for k, v in sys.modules.items():
        path = pathlib.Path(k)

        if 'cloudinit.config' == path.stem and path.suffix[1:4] == 'cc_':
            module_name = path.suffix[1:]
            members = inspect.getmembers(v)
            schemas[module_name] = None
            for name, value in members:
                if name == 'schema':
                    schemas[module_name] = value
                    break
    return schemas


def validate_cloudconfig_schema(schema):
    """Validate schema definition against strict metaschema.

    @param schema: jsonschema dict describing the supported schema definition
       for the cloud config module (config.cc_*)

    This is a modified version of the validation function in schema.py
    """
    try:
        from jsonschema import Draft4Validator, FormatChecker
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

    mymeta = cloudinitValidator.META_SCHEMA

    # this disables bottom-level keys
    mymeta['additionalProperties'] = False

    # encoding the base level jsonschema definitions
    # necessary since (since additionalProperties=False)
    mymeta['properties']['name'] = {'type': 'string'}
    mymeta['properties']['examples'] = {'type': 'array'}
    mymeta['properties']['distros'] = {'type': 'array'}
    mymeta['properties']['frequency'] = {'type': 'string'}
    cloudinitValidator.check_schema(schema)

    cloudinitValidator(schema, format_checker=FormatChecker())
