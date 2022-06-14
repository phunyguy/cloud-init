# This file is part of cloud-init. See LICENSE file for license information.

import contextlib
import errno
import os
import shutil
import tempfile

_TMPDIR = None
_ROOT_TMPDIR = "/run/cloud-init/tmp"

# This is for the person(s) trying to run cloud-init as root != 0
# I doubt anybody does this, but there is insufficient evidence of that to
# change current behavior for them.
_NON_ROOT_TMPDIR = "/tmp"


def _tempfile_dir_arg(odir=None, needs_exe=False):
    """Return the proper 'dir' argument for tempfile functions.

    When root, cloud-init will use /run/cloud-init/tmp to avoid
    any cleaning that a distro boot might do on /tmp (such as
    systemd-tmpfiles-clean).

    If the caller of this function (mkdtemp or mkstemp) was provided
    with a 'dir' argument, then that is respected.

    @param odir: original 'dir' arg to 'mkdtemp' or other.
    @param needs_exe: Boolean specifying whether or not exe permissions are
        needed for tempdir. This is needed because /run is mounted noexec.

    Presumably for performance reasons, the dir is cached
    """
    global _TMPDIR

    def make_the_dir_be(tdir):
        if not os.path.isdir(tdir):
            os.makedirs(tdir)
            os.chmod(tdir, 0o1700)

    if odir is not None:
        return odir

    if _TMPDIR:
        return _TMPDIR

    if needs_exe or os.getuid() == 0:
        make_the_dir_be(_ROOT_TMPDIR)
        _TMPDIR = _ROOT_TMPDIR
        return _ROOT_TMPDIR

    tdir = os.environ.get("TMPDIR", _NON_ROOT_TMPDIR)
    make_the_dir_be(tdir)

    _TMPDIR = tdir
    return tdir


def ExtendedTemporaryFile(**kwargs):
    kwargs["dir"] = _tempfile_dir_arg(
        kwargs.pop("dir", None), kwargs.pop("needs_exe", False)
    )
    fh = tempfile.NamedTemporaryFile(**kwargs)
    # Replace its unlink with a quiet version
    # that does not raise errors when the
    # file to unlink has been unlinked elsewhere..

    def _unlink_if_exists(path):
        try:
            os.unlink(path)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise e

    fh.unlink = _unlink_if_exists

    # Add a new method that will unlink
    # right 'now' but still lets the exit
    # method attempt to remove it (which will
    # not throw due to our del file being quiet
    # about files that are not there)
    def unlink_now():
        fh.unlink(fh.name)

    setattr(fh, "unlink_now", unlink_now)
    return fh


def tempdir(rmtree_ignore_errors=False, **kwargs):
    # This seems like it was only added in python 3.2
    # Make it since its useful...
    # See: http://bugs.python.org/file12970/tempdir.patch
    return tempfile.TemporaryDirectory(
        ignore_cleanup_errors=rmtree_ignore_errors, **kwargs
    )


def mkdtemp(**kwargs):
    kwargs["dir"] = _tempfile_dir_arg(
        kwargs.pop("dir", None), kwargs.pop("needs_exe", False)
    )
    return tempfile.mkdtemp(**kwargs)


def mkstemp(**kwargs):
    kwargs["dir"] = _tempfile_dir_arg(
        kwargs.pop("dir", None), kwargs.pop("needs_exe", False)
    )
    return tempfile.mkstemp(**kwargs)


# vi: ts=4 expandtab
