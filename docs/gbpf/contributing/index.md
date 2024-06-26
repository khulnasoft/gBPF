# How to contribute

Development happens on [GitHub](https://github.com/khulnasoft/gbpf) and contributions in
all forms are welcome. Please take a look at [the architecture](architecture.md) to get
a better understanding of the high-level goals.

## Developer Certificate of Origin

The Khulnasoft project requires that all contributions to project repositories carry the
[Developer Certificate of Origin][DCO]. This is as simple as appending a footer
to your commits:

```
Signed-off-by: Your Name <name@example.org>
```

Signing off your contributions this way means that you've read and understood
the contents of the DCO.

## Running the tests

Many of the tests require privileges to set resource limits and load gBPF code.
The easiest way to obtain these is to run the tests with `sudo`.

Run all tests with the following command:

```shell-session
go test -exec sudo ./...
```

To test the current package with a different kernel version you can use [vimto].
Once you have installed `vimto` and its dependencies you can run all tests on a
different kernel:

```shell-session
vimto -- go test ./...
```

Use one of the [precompiled kernels](https://github.com/khulnasoft/ci-kernels/pkgs/container/ci-kernels/versions) like so:

```shell-session
vimto -kernel :mainline -- go test ./...
```

## Regenerating testdata and source code

The library includes some binary artifacts which are used for tests and some
generated source code. Run `make` in the root of the repository to start
this process.

```shell-session
make
```

This requires Docker, as it relies on a standardized build
environment to keep the build output stable.
It is possible to regenerate data using Podman by overriding the `CONTAINER_*`
variables:

```shell-session
make CONTAINER_ENGINE=podman CONTAINER_RUN_ARGS=
```

### Updating kernel dependencies

Syscall bindings and some parameters required to parse ELF sections are derived
from upstream kernel versions. You can update them to the latest version by:

1. Adjusting the `KERNEL_VERSION` variable in `Makefile`
2. Running
    ```shell-session
    make update-kernel-deps
    ```

Finally, bump the tested kernels in `.github/workflows/ci.yml`

## Project Roles

If you'd like to contribute to the library more regularly, one of the
[maintainers][gbpf-lib-maintainers] can add you to the appropriate team or mark
you as a code owner. Please create an issue in the repository.

* [gbpf-go-contributors]
    * Have ["Triage"][permissions] role
    * May be asked to review certain parts of code
    * May be asked to help with certain issues
* [gbpf-go-reviewers]
    * Have ["Write"][permissions] role
    * CODEOWNER of a part of the code base
    * In-depth review of code, escalates to maintainers if necessary
        * For bugfixes: review within 1-2 days
        * Otherwise: review within a work week
        * When lacking time: escalate to maintainers, but don’t ignore
* [gbpf-lib-maintainers]
    * Have ["Admin"][permissions] role
    * Manage releases
    * Triage incoming issues and discussions and pull in CODEOWNERS if needed
    * Maintain CI & project permissions
    * Maintain roadmap and encourage contributions towards it
    * Merge approved PRs

[vimto]: https://github.com/lmb/vimto
[permissions]: https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/repository-roles-for-an-organization#permissions-for-each-role
[gbpf-go-contributors]: https://github.com/orgs/khulnasoft/teams/gbpf-go-contributors/members
[gbpf-go-reviewers]: https://github.com/orgs/khulnasoft/teams/gbpf-go-reviewers/members
[gbpf-lib-maintainers]: https://github.com/orgs/khulnasoft/teams/gbpf-lib-maintainers/members
[DCO]: https://developercertificate.org/
