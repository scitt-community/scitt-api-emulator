from dataclasses import dataclass, field
from typing import List, Any, Union

import cwt
import pycose.keys.ec2


@dataclass
class VerificationKey:
    transforms: List[Any]
    original: Any
    original_content_type: str
    original_bytes: bytes
    original_bytes_encoding: str
    usable: bool
    cwt: Union[cwt.COSEKey, None]
    cose: Union[pycose.keys.ec2.EC2Key, None]
