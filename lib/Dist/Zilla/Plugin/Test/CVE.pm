package Dist::Zilla::Plugin::Test::CVE;

use v5.20;

use Moose;

use Sub::Exporter::ForMethods 'method_installer';
use Data::Section 0.004 { installer => method_installer }, '-setup';
use Dist::Zilla::File::InMemory;
use Moose::Util::TypeConstraints qw( role_type );

use namespace::autoclean;

use experimental qw( signatures );

with qw(
  Dist::Zilla::Role::FileGatherer
  Dist::Zilla::Role::FileMunger
  Dist::Zilla::Role::TextTemplate
  Dist::Zilla::Role::PrereqSource
);

our $VERSION = '0.0.1';

has filename => (
    is      => 'ro',
    isa     => 'Str',
    lazy    => 1,
    default => sub { return 'xt/author/cve.t' },
);

has _file_obj => (
    is  => 'rw',
    isa => role_type('Dist::Zilla::Role::File'),
);

around dump_config => sub( $orig, $self ) {
    my $config = $self->$orig;
    $config->{ +__PACKAGE__ } = {
        filename => $self->filename,
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

    my $file = $self->_file_obj;
    $file->content(
        $self->fill_in_string(
            $file->content,
            {
                dist   => \( $self->zilla ),
                plugin => \$self,
            },
        )
    );
    return;
}

sub register_prereqs($self) {
    $self->zilla->register_prereqs(
        {
            phase => 'develop',
            type  => 'requires',
        },
        'Test2::Require::AuthorTesting' => 0,
        'Test2::V0'                     => 0,
        'Test::CVE'                     => '0.10',
    );
}

__PACKAGE__->meta->make_immutable;

1;

__DATA__
___[ __TEST__ ]___
#!perl

use v5.14;
use warnings;

use Test2::Require::AuthorTesting;

use Test2::V0;
use Test::CVE;

has_no_cves(
    author => 1,
    deps   => 1,
    core   => 1,
    perl   => 0,
);

done_testing;
