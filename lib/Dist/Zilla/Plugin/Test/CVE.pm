package Dist::Zilla::Plugin::Test::CVE;

# ABSTRACT: add tests for known CVEs

use v5.20;

use Moose;

use Sub::Exporter::ForMethods 'method_installer';
use Data::Dumper::Concise qw( Dumper );
use Data::Section 0.004 { installer => method_installer }, '-setup';
use Dist::Zilla ();
use Dist::Zilla::File::InMemory;
use PerlX::Maybe qw( maybe );
use Test::CVE ();
use Types::Common qw( ConsumerOf NonEmptyStr HashRef );

use namespace::autoclean;

use experimental qw( signatures );

with qw(
  Dist::Zilla::Role::FileGatherer
  Dist::Zilla::Role::FileMunger
  Dist::Zilla::Role::TextTemplate
  Dist::Zilla::Role::PrereqSource
);

our $VERSION = 'v0.1.0';

=begin :meta

=for stopwords CVEs

=for Pod::Coverage gather_files munge_files register_prereqs

=end :meta

=head1 SYNOPSIS

In the F<dist.ini>:

    [Test::CVE]
    filename = xt/author/cve.t
    author = 1
    deps   = 1
    core   = 1
    perl   = 0

=head1 DESCRIPTION

This is a L<Dist::Zilla> plugin to add L<Test::CVE> author tests to a distribution for known CVEs.

=cut

=option filename

This is the test filename.  It defaults to F<xt/author/cve.t>.

=cut

has filename => (
    is      => 'ro',
    isa     => NonEmptyStr,
    lazy    => 1,
    default => sub { return 'xt/author/cve.t' },
);

has _file_obj => (
    is  => 'rw',
    isa => ConsumerOf ['Dist::Zilla::Role::File'],
);

has _test_args => (
    is      => 'ro',
    isa     => HashRef,
    default => sub { {} },
);

around plugin_from_config => sub( $orig, $class, $name, $args, $section ) {
    my %module_args;

    for my $key ( keys $args->%* ) {
        if ( $key =~ s/^-// ) {
            die "$key cannot be set" if $key eq "_test_args";
            $module_args{$key} = $args->{"-$key"};
        }
        else {
            $module_args{_test_args}{$key} = $args->{$key};
        }
    }

    $module_args{filename} = delete $module_args{_test_args}{filename} if $module_args{_test_args}{filename};

    $module_args{_test_args}{author} //= 1;
    $module_args{_test_args}{deps}   //= 1;
    $module_args{_test_args}{core}   //= 1;
    $module_args{_test_args}{perl}   //= 0;

    return $class->$orig( $name, \%module_args, $section );
};

around dump_config => sub( $orig, $self ) {
    my $config = $self->$orig;
    $config->{ +__PACKAGE__ } = {
        filename   => $self->filename,
        _test_args => $self->_test_args,
        blessed($self) ne __PACKAGE__ ? ( version => $VERSION ) : (),
    };
    return $config;
};

sub gather_files($self) {

    $self->add_file(
        $self->_file_obj(
            Dist::Zilla::File::InMemory->new(
                name    => $self->filename,
                content => ${ $self->section_data('__TEST__') },
            )
        )
    );
    return;
}

sub munge_files($self) {

    my $args      = $self->_test_args;
    my $args_perl = my $text = Dumper($args) =~ s/\A\{/(/r =~ s/\}\n\Z/)/rm;

    my $author = $args->{author} ? "use Test2::Require::AuthorTesting;" : "";

    my $file = $self->_file_obj;
    $file->content(
        $self->fill_in_string(
            $file->content,
            {
                dist      => \( $self->zilla ),
                plugin    => \$self,
                author    => $author,
                args_perl => $args_perl,
            },
        )
    );
    return;
}

sub register_prereqs($self) {

    my $author = $self->_test_args->{author} ? 0 : undef;

    $self->zilla->register_prereqs(
        {
            phase => 'develop',
            type  => 'requires',
        },
        maybe
          'Test2::Require::AuthorTesting' => $author,
        'Test2::V0' => 0,
        'Test::CVE' => '0.10',
    );
}

__PACKAGE__->meta->make_immutable;

1;

=head1 SECURITY CONSIDERATIONS

This will only identify known CVEs in list dependencies.
It may not identify CVEs in undeclared prerequisites or deep prerequisites.

=cut

__DATA__
___[ __TEST__ ]___
#!perl

use v5.14;
use warnings;

{{ $author }}

use Test2::V0;
use Test::CVE;

has_no_cves{{ $args_perl }};

done_testing;
