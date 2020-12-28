using CrossPlatformDSA.DSA.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace CrossPlatformDSA.DSA.Models
{
    public class WindowsLib : ILibrary
    {
        private string OCSP_PATH = "http://ocsp.pki.gov.kz/";
        KalkanCryptCOMLib.KalkanCryptCOM _kalkan;
        private int kalkanFlag;
        private string outData, outVerifyInfo, outCert, errStr, outInfo;
        uint err;
        long outDateTime;
        DateTime currentLocalTime = DateTime.Now;
        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc); // Время в формате unix систем

        public WindowsLib()
        {
            _kalkan = new KalkanCryptCOMLib.KalkanCryptCOM();
            _kalkan.Init();
        }
        public bool VerifyData(byte[] data, out UserCertInfo userCertInfo)
        {
            userCertInfo = null;
            bool res = false;
            string base64StrCMS;
            base64StrCMS = Convert.ToBase64String(data);
            kalkanFlag = (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_SIGN_CMS +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_IN_BASE64 +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_OUT_BASE64 +
                   (int)KalkanCryptCOMLib.KALKANCRYPTCOM_FLAGS.KC_WITH_TIMESTAMP;
            _kalkan.VerifyData("", kalkanFlag, 1, "", base64StrCMS, out outData, out outVerifyInfo, out outCert);
            _kalkan.GetLastErrorString(out errStr, out err);

            if (err == 0)
            {
                res = true;
                try
                {
                    userCertInfo = GetUserCertificate(outCert, base64StrCMS);

                    byte[] bytesFromBase64 = Convert.FromBase64String(outData);
                    System.IO.File.WriteAllBytes(Path.Combine(Environment.CurrentDirectory, "sometext.txt"), bytesFromBase64);
                }
                catch (Exception ex)
                {
                    userCertInfo.extraInfo = ex.Message;
                }
                try
                {
                    // Проверка сертификата на отозванность на основе удостоверяющего центра OCSP
                    _kalkan.X509ValidateCertificate(outCert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_VALIDTYPE.KC_USE_OCSP, OCSP_PATH, currentLocalTime, out outInfo);
                    _kalkan.GetLastErrorString(out errStr, out err);
                    if (err != 0)
                    {
                        userCertInfo.extraInfo = errStr;
                    }
                    else
                    {
                        userCertInfo.withDrawSignKeyInfo = outInfo;
                    }
                }
                catch (Exception ex)
                {

                    userCertInfo.extraInfo = ex.Message;
                }


            }
            return res;
        }
        public UserCertInfo GetUserCertificate(string cert, string base64StrCMS)
        {
            UserCertInfo userCertInfo = new UserCertInfo();
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COMMONNAME, out userCertInfo.nameAndSurname);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_GIVENNAME, out userCertInfo.middleName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SURNAME, out userCertInfo.surname);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SERIALNUMBER, out userCertInfo.IIN);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_EMAIL, out userCertInfo.email);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTBEFORE, out userCertInfo.notBefore);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_NOTAFTER, out userCertInfo.notAfter);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN, out userCertInfo.serialNumberCert);

            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COUNTRYNAME, out userCertInfo.issuerCountryName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_SOPN, out userCertInfo.issuerSopn);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_LOCALITYNAME, out userCertInfo.issuerLocalityName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORG_NAME, out userCertInfo.issuerOrgName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_ORGUNIT_NAME, out userCertInfo.issuerOrgUnitName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_COMMONNAME, out userCertInfo.issuerCommonName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_COUNTRYNAME, out userCertInfo.subjectCountryName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_SOPN, out userCertInfo.subjectSopn);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_LOCALITYNAME, out userCertInfo.subjectLocalityName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORG_NAME, out userCertInfo.subjectOrgName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_ORGUNIT_NAME, out userCertInfo.subjectOrgUnitName);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_BC, out userCertInfo.subjectBc);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DC, out userCertInfo.subjectDc);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_KEY_USAGE, out userCertInfo.keyUsage);

            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_EXT_KEY_USAGE, out userCertInfo.extKeyUsage);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_AUTH_KEY_ID, out userCertInfo.authKeyId);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJ_KEY_ID, out userCertInfo.subjKeyId);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_CERT_SN, out userCertInfo.certSn);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_ISSUER_DN, out userCertInfo.issuerDn);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SUBJECT_DN, out userCertInfo.subjectDn);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_SIGNATURE_ALG, out userCertInfo.signatureAlg);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_PUBKEY, out userCertInfo.pubkey);
            _kalkan.X509CertificateGetInfo(cert, (int)KalkanCryptCOMLib.KALKANCRYPTCOM_CERTPROPID.KC_CERTPROP_POLICIES_ID, out userCertInfo.policiesId);

            _kalkan.TSAGetTimeFromSig(base64StrCMS, kalkanFlag, 0, out outDateTime);
            _kalkan.GetLastErrorString(out errStr, out err);
            if (err == 0)
            {
                userCertInfo.signTime = dateTime.AddSeconds(outDateTime).ToLocalTime();
            }


            // TODO проверить сертификат на отозванность



           // _kalkan.TSASetUrl
           // _kalkan.GetLastErrorString(out errStr, out err);

            return userCertInfo;
        }
    }
}
