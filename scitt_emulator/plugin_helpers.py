# Copyright (c) SCITT Authors.
# Licensed under the MIT License.
import os
import sys
import pathlib
import importlib
from typing import Iterator, Optional, Union, Any


def entrypoint_style_load(
    *args: str, relative: Optional[Union[str, pathlib.Path]] = None
) -> Iterator[Any]:
    """
    Load objects given the entrypoint formatted path to the object. Roughly how
    the python stdlib docs say entrypoint loading works.
    """
    # Push current directory into front of path so we can run things
    # relative to where we are in the shell
    if relative is not None:
        if relative == True:
            relative = os.getcwd()
        # str() in case of Path object
        sys.path.insert(0, str(relative))
    try:
        for entry in args:
            modname, qualname_separator, qualname = entry.partition(":")
            obj = importlib.import_module(modname)
            for attr in qualname.split("."):
                if hasattr(obj, "__getitem__"):
                    obj = obj[attr]
                else:
                    obj = getattr(obj, attr)
            yield obj
    finally:
        if relative is not None:
            sys.path.pop(0)
