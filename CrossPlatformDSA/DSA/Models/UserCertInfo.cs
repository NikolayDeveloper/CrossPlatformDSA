using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class UserCertInfo
    {
        public KeyValuePair<string, bool> TSP_exists { get; set; }
        public KeyValuePair<string, bool> ErrorExpiredOrInvalidWithoutKC_NOCHECKCERTTIME { get; set; }
        public KeyValuePair<string, bool> WarningExpiredOrInvalidWithKC_NOCHECKCERTTIME { get; set; }
        public KeyValuePair<string, bool> validCertificateMessage_ocsp { get; set; }
        public KeyValuePair<string, bool> validCertificateMessage_crl { get; set; }
        public KeyValuePair<string, bool> CMSvalidateMessage { get; set; }
       
        
        public string NameAndSurname { get; set; }
        public string Surname { get; set; }
        public string MiddleName { get; set; }
        public string IIN { get; set; }
        public string Email { get; set; }
        public string NotBefore { get; set; }
        public string NotAfter { get; set; }
        public DateTime SignTime { get; set; }
        public string SerialNumberCert { get; set; }
        public string ExtraInfo { get; set; }
        //public string extraInfo_ocsp;
        //public string extraInfo_crl;
        // public string validCertificateMessage_ocsp;
        //public string validCertificateMessage_crl;

        public string IssuerCountryName { get; set; }
        public string IssuerSopn { get; set; }
        public string IssuerLocalityName { get; set; }
        public string IssuerOrgName { get; set; }
        public string IssuerOrgUnitName { get; set; }
        public string IssuerCommonName { get; set; }
        public string SubjectCountryName { get; set; }
        public string SubjectSopn { get; set; }
        public string SubjectLocalityName { get; set; }
        public string SubjectOrgName { get; set; }
        public string SubjectOrgUnitName { get; set; }
        public string SubjectBc { get; set; }
        public string SubjectDc { get; set; }
        public string KeyUsage { get; set; }

        public string ExtKeyUsage { get; set; }
        public string AuthKeyId { get; set; }
        public string SubjKeyId { get; set; }
        public string CertSn { get; set; }
        public string IssuerDn { get; set; }
        public string SubjectDn { get; set; }
        public string SignatureAlg { get; set; }
        public string Pubkey { get; set; }
        public string PoliciesId { get; set; }
        /// <summary>
        /// Получение списка свойств UserCertInfo
        /// </summary>
        /// <returns></returns>
        public Dictionary<string, int> UserInfoList()
        {
            Dictionary<string, int> UserInfoList = new Dictionary<string, int>();
            UserInfoList.Add(nameof(NameAndSurname), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COMMONNAME);
            UserInfoList.Add(nameof(Surname), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SURNAME);
            UserInfoList.Add(nameof(MiddleName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_GIVENNAME);
            UserInfoList.Add(nameof(IIN), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SERIALNUMBER);
            UserInfoList.Add(nameof(Email), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_EMAIL);
            UserInfoList.Add(nameof(NotBefore), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTBEFORE);
            UserInfoList.Add(nameof(NotAfter), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTAFTER);
            UserInfoList.Add(nameof(SerialNumberCert), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN);
            UserInfoList.Add(nameof(IssuerCountryName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COUNTRYNAME);
            UserInfoList.Add(nameof(IssuerSopn), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_SOPN);
            UserInfoList.Add(nameof(IssuerLocalityName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_LOCALITYNAME);
            UserInfoList.Add(nameof(IssuerOrgName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORG_NAME);
            UserInfoList.Add(nameof(IssuerOrgUnitName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORGUNIT_NAME);
            UserInfoList.Add(nameof(IssuerCommonName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COMMONNAME);
            UserInfoList.Add(nameof(SubjectCountryName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COUNTRYNAME);
            UserInfoList.Add(nameof(SubjectSopn), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SOPN);
            UserInfoList.Add(nameof(SubjectLocalityName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_LOCALITYNAME);
            UserInfoList.Add(nameof(SubjectOrgName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORG_NAME);
            UserInfoList.Add(nameof(SubjectOrgUnitName), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORGUNIT_NAME);
            UserInfoList.Add(nameof(SubjectBc), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_BC);
            UserInfoList.Add(nameof(SubjectDc), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DC);
            UserInfoList.Add(nameof(KeyUsage), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_KEY_USAGE);
            UserInfoList.Add(nameof(ExtKeyUsage), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_EXT_KEY_USAGE);
            UserInfoList.Add(nameof(AuthKeyId), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_AUTH_KEY_ID);
            UserInfoList.Add(nameof(SubjKeyId), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJ_KEY_ID);
            UserInfoList.Add(nameof(CertSn), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN);
            UserInfoList.Add(nameof(IssuerDn), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_DN);
            UserInfoList.Add(nameof(SubjectDn), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DN);
            UserInfoList.Add(nameof(SignatureAlg), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG);
            UserInfoList.Add(nameof(Pubkey), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_PUBKEY);
            UserInfoList.Add(nameof(PoliciesId), (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_POLICIES_ID);

            return UserInfoList;
        }
    }
}
