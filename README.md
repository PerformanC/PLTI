# PLTI

PerformanC's simplest and most efficient PLT hooking library, written in C99.

## Features

- C99 compliant
- Low complexity
- Simple API
- Minimal traces left

## Documentation

1. `bool plti_init(struct plti *ctx)`

Initializes the PLTI context. Must be initialized only once per process you want to hook.

2. `bool plti_add_lib(struct plti *ctx, const char *lib_name)`

Adds a library to the PLTI context, allowing it to have its PLT entries hooked. The library must be already loaded in the process.

3. `bool plti_add_manual_lib(struct plti *ctx, const char *lib_path, void *base_addr)`

Adds a library to the PLTI context manually, in case it is not findable with `dl_iterate_phdr`. The library must be accessible in the file system.

4. `bool plti_add_hook(struct plti *ctx, const char *lib_name, const char *name, void *new_callback, void **backup)`

Hooks a PLT entry by its name, replacing it with the provided callback. The original function address is stored in `backup` if it's not NULL (permanent hook).

5. `bool plti_add_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void *new_callback, void **backup)`

Hooks a PLT entry by its name prefix, replacing it with the provided callback. The original function address is stored in `backup` if it's not NULL (permanent hook).

6. `bool plti_remove_hook(struct plti *ctx, const char *lib_name, const char *name, void **backup)`

Removes a hook from a PLT entry by its name, restoring the original function address. Same as `plti_add_hook` but in reverse.

7. `bool plti_remove_hook_by_prefix(struct plti *ctx, const char *lib_name, const char *name_prefix, void **backup)`

Removes a hook from a PLT entry by its name prefix, restoring the original function address. Same as `plti_add_hook_by_prefix` but in reverse.

8. `bool plti_deinit(struct plti *ctx)`

Deinitializes the PLTI context, freeing all allocated resources. Must be called once when you are done with all hooking operations.

## Support

Any question or issue related to PLTI or other PerformanC projects can be made in our:

- [Discord server](https://discord.gg/uPveNfTuCJ)
- [Telegram chat](https://t.me/performancorg)
- [Signal group](https://signal.performanc.org)

## Contribution

It is mandatory to follow the PerformanC's [contribution guidelines](https://github.com/PerformanC/contributing) to contribute to PLTI. Following its Security Policy, Code of Conduct and syntax standard.

## Projects using PLTI

- [ReZygisk](https://github.com/PerformanC/ReZygisk): Transparent Zygisk implementation

## License

PLTI is licensed under [BSD 3-Clause License](LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/licenses/BSD-3-Clause).

* This project is considered as: [leading standard](https://github.com/PerformanC/contributing?tab=readme-ov-file#project-information).
