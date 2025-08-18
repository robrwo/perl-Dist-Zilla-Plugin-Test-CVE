# NAME

Dist::Zilla::Plugin::Test::CVE - add tests for known CVEs

# SYNOPSIS

In the `dist.ini`:

```
[Test::CVE]
filename = xt/author/cve.t
author = 1
deps   = 1
core   = 1
perl   = 0
```

# DESCRIPTION

This is a [Dist::Zilla](https://metacpan.org/pod/Dist%3A%3AZilla) plugin to add [Test::CVE](https://metacpan.org/pod/Test%3A%3ACVE) author tests to a distribution for known CVEs.

# REQUIREMENTS

This module lists the following modules as runtime dependencies:

- [Data::Dumper::Concise](https://metacpan.org/pod/Data%3A%3ADumper%3A%3AConcise)
- [Data::Section](https://metacpan.org/pod/Data%3A%3ASection) version 0.004 or later
- [Dist::Zilla](https://metacpan.org/pod/Dist%3A%3AZilla)
- [Moose](https://metacpan.org/pod/Moose)
- [PerlX::Maybe](https://metacpan.org/pod/PerlX%3A%3AMaybe)
- [Sub::Exporter::ForMethods](https://metacpan.org/pod/Sub%3A%3AExporter%3A%3AForMethods)
- [Test::CVE](https://metacpan.org/pod/Test%3A%3ACVE)
- [Types::Common](https://metacpan.org/pod/Types%3A%3ACommon)
- [experimental](https://metacpan.org/pod/experimental)
- [namespace::autoclean](https://metacpan.org/pod/namespace%3A%3Aautoclean)
- [perl](https://metacpan.org/pod/perl) version v5.20.0 or later

See the `cpanfile` file for the full list of prerequisites.

# INSTALLATION

The latest version of this module (along with any dependencies) can be installed from [CPAN](https://www.cpan.org) with the `cpan` tool that is included with Perl:

```
cpan Dist::Zilla::Plugin::Test::CVE
```

You can also extract the distribution archive and install this module (along with any dependencies):

```
cpan .
```

You can also install this module manually using the following commands:

```
perl Makefile.PL
make
make test
make install
```

If you are working with the source repository, then it may not have a `Makefile.PL` file.  But you can use the [Dist::Zilla](https://dzil.org/) tool in anger to build and install this module:

```
dzil build
dzil test
dzil install --install-command="cpan ."
```

For more information, see [How to install CPAN modules](https://www.cpan.org/modules/INSTALL.html).

# SUPPORT

Only the latest version of this module will be supported.

This module requires Perl v5.20 or later.  Future releases may only support Perl versions released in the last ten
years.

## Reporting Bugs and Submitting Feature Requests

Please report any bugs or feature requests on the bugtracker website
[https://github.com/robrwo/perl-Dist-Zilla-Plugin-Test-CVE/issues](https://github.com/robrwo/perl-Dist-Zilla-Plugin-Test-CVE/issues)

When submitting a bug or request, please include a test-file or a
patch to an existing test-file that illustrates the bug or desired
feature.

If the bug you are reporting has security implications which make it inappropriate to send to a public issue tracker,
then see `SECURITY.md` for instructions how to report security vulnerabilities.

# SOURCE

The development version is on github at [https://github.com/robrwo/perl-Dist-Zilla-Plugin-Test-CVE](https://github.com/robrwo/perl-Dist-Zilla-Plugin-Test-CVE)
and may be cloned from [git://github.com/robrwo/perl-Dist-Zilla-Plugin-Test-CVE.git](git://github.com/robrwo/perl-Dist-Zilla-Plugin-Test-CVE.git)

# AUTHOR

Robert Rothenberg <rrwo@cpan.org>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2025 by Robert Rothenberg.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
