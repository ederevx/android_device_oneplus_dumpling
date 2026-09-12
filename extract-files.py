#!/usr/bin/env -S PYTHONPATH=../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: 2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

import hashlib
from pathlib import Path

from extract_utils.main import (
    ExtractUtils,
    ExtractUtilsModule,
)
from extract_utils.fixups_blob import (
    blob_fixup,
    blob_fixups_user_type,
)

namespace_imports = [
    'hardware/oneplus',
    'hardware/qcom-caf/sdm660',
    'hardware/qcom-caf/msm8998',
    'vendor/oneplus/msm8998-common',
]


def fixup_camera(ctx, file, file_path, *args, **kwargs):
    path = Path(file_path)
    data = path.read_bytes()
    output_hash = '9372ff57651bb05aa46d3707f35b0fe4cf012157f7fad8c745b1eb3374360d85'
    input_hash = '29a87956a219634c97385b4e1a7e6b1fb9e89f00c703b665295512e9b47ed954'
    current_hash = hashlib.sha256(data).hexdigest()
    if current_hash == output_hash:
        return
    if current_hash != input_hash:
        raise ValueError(f'Unexpected camera.msm8998.so hash: {current_hash}')
    replacements = (
        (bytes.fromhex('c168d0e90d20cde90320'), bytes.fromhex('c168d0e91220cde90320')),
        (bytes.fromhex('3168089a0026496bcbe90421'), bytes.fromhex('3168089a0026896ccbe90421')),
    )
    for old, new in replacements:
        if data.count(old) != 1 or data.count(new) != 0:
            raise ValueError('Unexpected camera.msm8998.so patch pattern count')
        data = data.replace(old, new)
    if hashlib.sha256(data).hexdigest() != output_hash:
        raise ValueError('camera.msm8998.so output hash mismatch')
    path.write_bytes(data)


# This table needs scalar 0x7c entries rather than an i8-splat sentinel.
def fixup_iface_scalar_sentinel(ctx, file, file_path, *args, **kwargs):
    path = Path(file_path)
    data = path.read_bytes()
    input_hash = '13462b063fd3a058da41135f42889091990e95062de837de17afffe06a32d15e'
    output_hash = '25055af3eda3661d6535bd98fd0d950dbc6e29624ff9f1192087834587bfac20'
    context_offset = 0x2455E
    instruction_offset = 0x2456E
    old_context = bytes.fromhex(
        '00f5c03040f6845100f5ac701af09aebc7ef5c0e0aa8002e40f90d0a40f9cf0a'
        '19d0bbf1000f16d0306c08282cd3dff8'
    )
    old_instruction = bytes.fromhex('c7ef5c0e')
    new_instruction = bytes.fromhex('c7ef5c00')
    current_hash = hashlib.sha256(data).hexdigest()
    if current_hash == output_hash:
        return
    if current_hash != input_hash:
        raise ValueError(
            f'Unexpected libmmcamera2_iface_modules.so hash: {current_hash}'
        )
    if data.count(old_context) != 1 or data.find(old_context) != context_offset:
        raise ValueError('Unexpected IFACE scalar-sentinel context count or offset')
    if data[instruction_offset:instruction_offset + len(old_instruction)] != old_instruction:
        raise ValueError('Unexpected IFACE scalar-sentinel instruction')
    data = (
        data[:instruction_offset]
        + new_instruction
        + data[instruction_offset + len(old_instruction):]
    )
    if hashlib.sha256(data).hexdigest() != output_hash:
        raise ValueError('libmmcamera2_iface_modules.so output hash mismatch')
    path.write_bytes(data)


blob_fixups: blob_fixups_user_type = {
    (
        'vendor/lib/hw/fingerprint.goodix.so',
        'vendor/lib64/hw/fingerprint.goodix.so',
    ): blob_fixup()
        .binary_regex_replace(b'\x00goodix.fingerprint\x00', b'\x00fingerprint\x00\x00\x00\x00\x00\x00\x00\x00'),
    'vendor/lib/hw/camera.msm8998.so': blob_fixup().call(fixup_camera, need_tmp_dir=False),
    'vendor/lib/libmmcamera2_iface_modules.so': blob_fixup().call(
        fixup_iface_scalar_sentinel, need_tmp_dir=False
    ),
}  # fmt: skip

module = ExtractUtilsModule(
    'dumpling',
    'oneplus',
    blob_fixups=blob_fixups,
    namespace_imports=namespace_imports,
    add_firmware_proprietary_file=True,
)

if __name__ == '__main__':
    utils = ExtractUtils.device_with_common(
        module, 'msm8998-common', module.vendor
    )
    utils.run()
