#!/usr/bin/env -S PYTHONPATH=../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: 2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

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

blob_fixups: blob_fixups_user_type = {
    (
        'vendor/lib/hw/fingerprint.goodix.so',
        'vendor/lib64/hw/fingerprint.goodix.so',
    ): blob_fixup()
        .binary_regex_replace(b'\x00goodix.fingerprint\x00', b'\x00fingerprint\x00\x00\x00\x00\x00\x00\x00\x00'),
    # private_handle_t size/offset: old 0x34/0x38 -> commonsys-intf 0x48/0x4c
    'vendor/lib/hw/camera.msm8998.so': blob_fixup()
        .sig_replace(
            'C1 68 D0 E9 0D 20 CD E9 03 20',
            'C1 68 D0 E9 12 20 CD E9 03 20',
        )
        .sig_replace(
            '31 68 08 9A 00 26 49 6B CB E9 04 21',
            '31 68 08 9A 00 26 89 6C CB E9 04 21',
        ),
    # this table needs scalar 0x7c entries, not an i8-splat sentinel
    'vendor/lib/libmmcamera2_iface_modules.so': blob_fixup()
        .sig_replace(
            '00 F5 C0 30 40 F6 84 51 00 F5 AC 70 1A F0 9A EB C7 EF 5C 0E 0A A8 00 2E 40 F9 0D 0A 40 F9 CF 0A 19 D0 BB F1 00 0F 16 D0 30 6C 08 28 2C D3 DF F8',
            '00 F5 C0 30 40 F6 84 51 00 F5 AC 70 1A F0 9A EB C7 EF 5C 00 0A A8 00 2E 40 F9 0D 0A 40 F9 CF 0A 19 D0 BB F1 00 0F 16 D0 30 6C 08 28 2C D3 DF F8',
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
