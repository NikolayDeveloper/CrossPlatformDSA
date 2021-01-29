using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class UserCertInfo
    {
        public KeyValuePair<string,bool> TSP_exists;
        public KeyValuePair<string, bool> ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME;
        public KeyValuePair<string, bool> WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME;
        public KeyValuePair<string, bool> validCertificateMessage_ocsp;
        public KeyValuePair<string, bool> validCertificateMessage_crl;
        public KeyValuePair<string, bool> CMSvalidateMessage;
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
        //public string extraInfo_ocsp;
        //public string extraInfo_crl;
       // public string validCertificateMessage_ocsp;
        //public string validCertificateMessage_crl;

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
