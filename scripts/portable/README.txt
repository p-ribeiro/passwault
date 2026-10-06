PASSWAULT PORTABLE
==================

Runs from this folder on any x86_64 Linux or WSL2 machine. Nothing is
installed on the host and no Python is needed.

    sh /path/to/passwault/passwault <command>

Tip: alias passwault='sh /media/$USER/STICK/passwault/passwault'
     (on WSL the stick is a drive letter, e.g. /mnt/e/passwault/passwault)


FIRST TIME
    passwault vault init                    create the encrypted vault
    passwault vault init --import-db FILE   or start from an existing
                                            passwault.db / passwault_*.db.gz
    passwault auth register -u NAME         create your user

EVERY TIME
    passwault vault open                    unlock the vault on this machine
    passwault auth login -u NAME
    passwault get -n github
    passwault vault close                   save, wipe the host copy, log out
                                            (then eject the drive)

TWO PASSWORDS
    The vault password unlocks the drive's database file. Your master
    password unlocks your entries inside it, as in the installed version.


WHERE THINGS LIVE
    data/vault.pwv        encrypted vault (vault.pwv.bak is the previous save)
    data/results/         images written by `passwault imagepass encode`
    backups/              `passwault backup create` copies, still encrypted.
                          Use `backup create -o DIR` to keep one off the stick.
    host RAM              decrypted copy while open, in
                          $XDG_RUNTIME_DIR/passwault-*/ (or /dev/shm)

SAFETY NOTES
    * The vault closes itself after 30 minutes without use (checked on the
      next command). If you unplug without `vault close`, the decrypted copy
      stays in host RAM until the next run there, `vault close --discard`,
      or a reboot.
    * Changes are written back to the drive after every command.
    * If the drive was used on another machine without closing here first,
      unsaved changes from this machine go to data/vault.pwv.conflict-<date>.
      Rename it to vault.pwv to use that version instead.
