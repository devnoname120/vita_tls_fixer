#include "tls_fixer/x509_names.h"
#include <string.h>

const char *tls_fixer_x509_attribute_name(const unsigned char *oid, size_t length) {
    static const struct { unsigned char number; const char *name; } attributes[] = {
        {3, "commonName"}, {6, "countryName"}, {7, "localityName"},
        {8, "stateOrProvinceName"}, {10, "organizationName"},
        {11, "organizationalUnitName"}, {5, "serialNumber"},
    };
    static const unsigned char email[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01};
    if (oid == NULL) {
        return NULL;
    }
    if (length == 3 && oid[0] == 0x55 && oid[1] == 0x04) {
        for (size_t index = 0; index < sizeof(attributes) / sizeof(attributes[0]); ++index) {
            if (attributes[index].number == oid[2]) {
                return attributes[index].name;
            }
        }
    }
    if (length == sizeof(email) && memcmp(oid, email, sizeof(email)) == 0) {
        return "emailAddress";
    }
    return NULL;
}
