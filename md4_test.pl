use Digest::Perl::MD4 qw(md4 md4_hex);

my $errors = 0;

$| = 1;

sub Printable {
    my $a = shift;
    my @A = split(//,$a);
    join '', map { (ord($_) >= 040 && ord($_) < 0177
		    ? $_
		    : sprintf("\\x%02x", ord($_))) } @A;
}

sub Check {
    my ($data, $result) = @_;
    my $hash = md4_hex($data);
    print 'MD4 ("', Printable($data), "\") = $hash\n";
    $errors++, warn "Expected $result instead\n" if $hash ne $result;
}

Check("", '31d6cfe0d16ae931b73c59d7e0c089c0');
Check("a", 'bde52cb31de33e46245e05fbdbd6fb24');
Check("abc", 'a448017aaf21d8525fc10ae87aa6729d');
Check("message digest", 'd9130a8164549fe818874806e1c7014b');
Check("abcdefghijklmnopqrstuvwxyz", 'd79e1c308aa5bbcdeea8ed63df412da9');
Check("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      '043f8582f241db351ce627e153e7f0e4');
Check("1234567890123456789012345678901234567890123456789012345678901234" .
      "5678901234567890",
      'e33b4ddc9c38f2199c3e7b164fcc0536');
# From CPAN Digest-MD4-1.1:
#  From draft-ietf-pppext-mschap-00.txt:
Check("\x4D\x00\x79\x00\x50\x00\x77\x00"
      => "fc156af7edcd6c0edde3337d427f4eac");

# From draft-brezak-win2k-krb-rc4-hmac-03.txt

sub Unicode {
    pack 'v*', unpack 'C*', $_[0];
}
Check(Unicode("foo") => "ac8e657f83df82beea5d43bdaf7800cc");

die "MD4 Test Failed with $errors errors.\n" if $errors;
print "MD4 Test Succeeded\n";
