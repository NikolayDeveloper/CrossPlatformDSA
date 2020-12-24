using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class UserCertInfo
    {
        public string nameAndSurname;
        public string surname;
        public string middleName;
        public string IIN;
        public string email;
        public string notBefore;
        public string notAfter;
        public DateTime signTime;
        public string serialNumberCert;
        public string extraInfo;
        public string withDrawSignKeyInfo;

        public string issuerCountryName;
        public string issuerSopn;
        public string issuerLocalityName;
        public string issuerOrgName;
        public string issuerOrgUnitName;
        public string issuerCommonName;
        public string subjectCountryName;
        public string subjectSopn;
        public string subjectLocalityName;
        public string subjectOrgName;
        public string subjectOrgUnitName;
        public string subjectBc;
        public string subjectDc;
        public string keyUsage;

        public string extKeyUsage;
        public string authKeyId;
        public string subjKeyId;
        public string certSn;
        public string issuerDn;
        public string subjectDn;
        public string signatureAlg;
        public string pubkey;
        public string policiesId;
    }
}
