import pathlib
import subprocess
import sys

cap = pathlib.Path(sys.argv[1])


def plist_version(bundle):
    info = pathlib.Path('/Library/Extensions/%s.kext/Contents/Info.plist' % bundle)
    if not info.is_file():
        return 'absent'
    return subprocess.check_output(
        ['/usr/libexec/PlistBuddy', '-c', 'Print :CFBundleVersion', str(info)],
        text=True).strip()


lines = [
    'kernel_release    : %s' % subprocess.check_output(['uname', '-r'], text=True).strip(),
    'kernel_version    : %s' % subprocess.check_output(['uname', '-v'], text=True).strip(),
    'hostname          : %s' % subprocess.check_output(['hostname'], text=True).strip(),
    'date_utc          : %s' % subprocess.check_output(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'],
                                                      text=True).strip(),
]
for bundle in ('RTL812xLucy', 'AMDMapperProbe'):
    lines.append('%s_version   : %s' % (bundle, plist_version(bundle)))
(cap / 'system.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('\n'.join(lines))
