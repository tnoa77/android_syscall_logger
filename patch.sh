#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 Ziqi Zhang <zq9120@yeah.net>. All Rights Reserved.

if ! [[ -d .git && -f drivers/base/Makefile && -f drivers/base/Kconfig ]]; then
	echo "Please run this from the top level of your kernel tree." >&2
	exit 1
fi

FILES="${0%/*}"

echo "[+] Patching"
cp "$FILES"/syscall_logger.c drivers/base/syscall_logger.c
grep -q ASSISTED_SYSCALL_LOGGER drivers/base/Makefile || cat "$FILES"/Kbuild.addon >> drivers/base/Makefile
grep -q ASSISTED_SYSCALL_LOGGER drivers/base/Kconfig || cat "$FILES"/Kconfig.addon >> drivers/base/Kconfig

#echo "[+] Committing"
#git add drivers/base/syscall_logger.c drivers/base/Makefile drivers/base/Kconfig
#git commit -s -F "$FILES"/commit-message.txt drivers/base/syscall_logger.c drivers/base/Makefile drivers/base/Kconfig

echo "[+] Done!"

echo "[*] Remember to enable CONFIG_ASSISTED_SYSCALL_LOGGER=y for this to work. Then simply use \`qi\` for root."
