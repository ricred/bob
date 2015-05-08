#!/usr/bin/perl
#
# draft-ietf-jose-json-web-signature
# A.3: Example JWS using ECDSA P-256 SHA-256

use strict;
use warnings;

use JSON;
use MIME::Base64 qw(decode_base64url);
use Digest::SHA qw(sha256);
use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::Bignum::CTX;
use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::ECDSA;

my $input_file = "es256-input.json";
my $key_file   = "es256-key.json";
my $sig_file   = "es256-signature.json";

my $input_json;
my $key_json;
my $sig_json;

my $fh;

sub hexdump {
    my $data = shift;
    return sprintf("%s (%d bytes)", unpack("H*", $data), length($data));
}

sub read_key {
    my $file = shift;

    my $json;

    open($fh, "<", $file);
    while (<$fh>) {
        $json .= $_;
    }
    close($fh);

    my $jwk = decode_json($json);

    my $x = decode_base64url($jwk->{x});
    my $y = decode_base64url($jwk->{y});
    my $d = decode_base64url($jwk->{d});

    my $bx = Crypt::OpenSSL::Bignum->new_from_bin($x);
    my $by = Crypt::OpenSSL::Bignum->new_from_bin($y);
    my $bd = Crypt::OpenSSL::Bignum->new_from_bin($d);

    unless ($bx and $by and $bd) {
        die "failed to parse EC key";
    }

    my $nid;

    if ($jwk->{crv} eq "P-256") {
        $nid = 415;    # NID_X9_62_prime256v1
    } elsif ($jwk->{crv} eq "P-384") {
        $nid = 715;    # NID_secp384r1
    } elsif ($jwk->{crv} eq "P-521") {
        $nid = 716;    # NID_secp521r1
    } else {
        die "unknown EC curve";
    }

    my $group   = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name($nid);
    my $private = $bd;
    my $public  = Crypt::OpenSSL::EC::EC_POINT::new($group) || die;
    my $ctx     = Crypt::OpenSSL::Bignum::CTX->new() || die;

    Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp($group,
        $public, $bx, $by, $ctx)
      || die;

    my $key = Crypt::OpenSSL::EC::EC_KEY::new();
    $key->set_group($group);
    Crypt::OpenSSL::EC::EC_KEY::set_private_key($key, $private) || die;
    Crypt::OpenSSL::EC::EC_KEY::set_public_key($key, $public) || die;

    return $key;
}

#
# read input octet sequence
#
open($fh, "<", $input_file);
while (<$fh>) {
    $input_json .= $_;
}
close($fh);
my $input_data = decode_json($input_json);

my $input = pack("C*", @{$input_data});
print STDERR "Input data: ", hexdump($input), "\n";

#
# read key
#
my $eckey = read_key($key_file);
print STDERR "private=", $eckey->get0_private_key()->to_decimal, "\n";
print STDERR "public=", $eckey->get0_public_key(), "\n";

#
# read reference signature
#
open($fh, "<", $sig_file);
while (<$fh>) {
    $sig_json .= $_;
}
close($fh);
my $sig_data = decode_json($sig_json);
my $ref_sig_r =
  Crypt::OpenSSL::Bignum->new_from_bin(decode_base64url($sig_data->{r}));
my $ref_sig_s =
  Crypt::OpenSSL::Bignum->new_from_bin(decode_base64url($sig_data->{s}));
print STDERR "ref r=", $ref_sig_r->to_hex, "\n";
print STDERR "ref s=", $ref_sig_s->to_hex, "\n";
my $ref_sig = $ref_sig_r->to_hex . $ref_sig_s->to_hex;

#
# verify (can't sign and compare, as this is ECDSA)
#
my $digest = sha256($input);
my $sig    = Crypt::OpenSSL::ECDSA::ECDSA_SIG->new();
$sig->set_r($ref_sig_r->to_bin);
$sig->set_s($ref_sig_s->to_bin);
my $verify = Crypt::OpenSSL::ECDSA::ECDSA_do_verify($digest, $sig, $eckey);

#
# compare
#
if ($verify) {
    print "Signature validation successful\n";
    exit 0;
} else {
    print "Signature validation failed\n";
    exit 1;
}
