#!/usr/bin/env bash
export GCC5_RISCV64_PREFIX=riscv64-linux-gnu-
export PACKAGES_PATH=/edk2
export EDK_TOOLS_PATH=/edk2/BaseTools

cd /edk2

# We pass parameters to this script. But those parameters are passed to a
# sourced script and edksetup.sh must not take arguments.  So we have to save
# the arguments of this script before sourcing and restore them later.
ARGS=( "$@" )
set -- # Clear argv
. ./edksetup.sh
set -- "${ARGS[@]}" # Restore argv

$@
