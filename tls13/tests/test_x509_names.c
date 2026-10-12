#include "tls_fixer/x509_names.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char oid[] = {0x55, 0x04, 0x03};
    static const struct { unsigned char number; const char *name; } cases[] = {
        {3, "commonName"}, {6, "countryName"}, {7, "localityName"},
        {8, "stateOrProvinceName"}, {10, "organizationName"},
        {11, "organizationalUnitName"}, {5, "serialNumber"},
    };
    static const unsigned char email[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        oid[2] = cases[i].number;
        assert(strcmp(tls_fixer_x509_attribute_name(oid, sizeof(oid)), cases[i].name) == 0);
    }
    assert(strcmp(tls_fixer_x509_attribute_name(email, sizeof(email)), "emailAddress") == 0);
    assert(tls_fixer_x509_attribute_name(NULL, 3) == NULL);
    assert(tls_fixer_x509_attribute_name(oid, 0) == NULL);
    assert(tls_fixer_x509_attribute_name(oid, 2) == NULL);
    oid[2] = 0xff;
    assert(tls_fixer_x509_attribute_name(oid, sizeof(oid)) == NULL);
    puts("X.509 attribute names: PASS");
    return 0;
}
