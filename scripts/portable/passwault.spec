# PyInstaller spec for the portable one-file build (run via scripts/build_portable.sh).
import os
import platform

# manylinux-allowed system libraries: the target host provides them, and bundling
# this build host's newer copies would raise the binary's minimum glibc.
HOST_LIBS = ("libgcc_s.so", "libstdc++.so", "libz.so")

a = Analysis(
    [os.path.join(SPECPATH, "entry.py")],
    hiddenimports=["sqlalchemy.dialects.sqlite.pysqlite"],
    excludes=["pytest", "_pytest", "psycopg2"],
)
a.binaries = [b for b in a.binaries if not os.path.basename(b[0]).startswith(HOST_LIBS)]

# Lets the build script check the glibc floor of what was actually bundled
with open(os.path.join(workpath, "binaries.txt"), "w") as f:
    f.write("\n".join(src for _, src, _ in a.binaries))

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=f"passwault-linux-{platform.machine()}",
    console=True,
    upx=False,
)
